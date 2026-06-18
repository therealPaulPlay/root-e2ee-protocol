# ROOT (Protocol)

End-to-end encrypted communication protocol with two parts: A JS client package, and a Go server package. Uses CBOR for serialization and comes with a built-in key-renewal system for forward secrecy.

## Install

```sh
# JS
npm install root-e2ee-protocol

# Go
go get github.com/therealPaulPlay/root-e2ee-protocol/go-server
```

## Model

- Key ownership: The server has one long-lived private key per key type, shared across all clients. Each client has one private key per server it talks to.
- Key renewal: Only the client initiates renewal. The server is reactive.
- Response expectations: Clients always get a response to a request, while servers can push messages without expecting anything back.
- Ordering: Requests do not guarantee arrival order. Use `await` before the next request if strict ordering is needed. Push handlers fire whenever a push arrives and may interleave with requests, a push initiated before a request may arrive after its response.

## JS client

Package: `root-e2ee-protocol`.

### Class: `Client`

Constructor accepts a single object with the following properties.

| Property | Type | Description |
|---|---|---|
| `selfId` | `string` | The client's own ID. Sent as `originId` on every outbound envelope. |
| `keyStore` | `KeyStore` | Host-implemented object (see below) that owns key persistence. |
| `requestTimeoutMs` | `number?` | How long `request` waits for a matching response before rejecting. Default `10000`. |
| `keyMaxAgeMs` | `number?` | When the current key's `createdAt` is older than this, `request` runs a renewal handshake before sending. Default `300000`. |

Methods:

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `request` | `serverId: string`, `type: string`, `payload: any`, `write: WriteFn` | `Promise<any>` | Encrypt and send a request, resolve with the decoded response payload. Rejects on protocol-level failures. |
| `receive` | `bytes: Uint8Array` | `void` | Entry point for every inbound envelope. Host needs to call this for each message off the wire. |
| `onPush` | `serverId: string`, `type: string`, `handler: PushHandler` | `void` | Register a push handler scoped to `(serverId, type)`. Multiple handlers are supported and fire in registration order. |
| `offPush` | `serverId: string`, `type: string`, `handler: PushHandler` | `void` | Remove a previously-registered push handler. |
| `close` | — | `void` | Call when the client is no longer needed so pending requests reject immediately instead of waiting for their timeout. |


Parameter function types:

| Type | Signature | Description |
|---|---|---|
| `WriteFn` | `(bytes: Uint8Array) => void \| Promise<void>` | Host-provided function that writes envelope bytes onto the wire. Called by the library from inside `request`. |
| `PushHandler` | `(payload: any, error: RelayError \| null) => void \| Promise<void>` | Registered via `onPush`, fires for server-initiated messages of a given `(serverId, type)`. On protocol errors, `error` is set. |

### Type: `KeyStore`

The host implements this interface and passes an instance to the `Client` constructor. The library calls these methods to read and persist key material during requests and renewals.

| Method | Parameters | Returns | Expected behavior |
|---|---|---|---|
| `getServerPublicKey` | `serverId: string` | `Promise<{ publicKey: Uint8Array, keyType: string } \| null>` | Return the server's public key and its type for this server, or `null` if none is stored. |
| `getCurrentPrivateKey` | `serverId: string` | `Promise<{ privateKey: Uint8Array, keyType: string, createdAt: number } \| null>` | Return the client's current private key for this server, its `keyType`, and the timestamp in ms where it was installed. Return `null` if no key is stored. |
| `getPreviousPrivateKey` | `serverId: string` | `Promise<{ privateKey: Uint8Array, keyType: string } \| null>` | Return the private key (and its `keyType`) that was current immediately before the most recent renewal, or `null` if none is retained. |
| `commitNewPrivateKey` | `serverId: string`, `newKey: { privateKey: Uint8Array, keyType: string }` | `Promise<void>` | Atomically move the current private key into previous and install `newKey` as the new current, with `createdAt` set to now. |
| `revertToPreviousPrivateKey` | `serverId: string` | `Promise<void>` | Swap previous into current and clear previous. Called when the server reports `DECRYPTION_FAILED`, indicating the two sides fell out of sync during a prior renewal. |

### Class: `SessionAES256GCM`

Returned by `deriveSessionP256`. Provides AES-256-GCM encryption for use cases outside the request/response flow.

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `encrypt` | `data: Uint8Array`, `aad?: Uint8Array` | `Promise<Uint8Array>` | Encrypt `data`. Output format is `nonce(12) \|\| ciphertext \|\| tag(16)`. `aad` is optional additional authenticated data. |
| `decrypt` | `bytes: Uint8Array`, `aad?: Uint8Array` | `Promise<Uint8Array>` | Decrypt bytes produced by `encrypt`. `aad` must match whatever was passed to `encrypt`. |

### Functions

| Function | Parameters | Returns | Description |
|---|---|---|---|
| `generateKeypairP256` | — | `Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }>` | Generate a fresh P-256 keypair. `publicKey` is raw uncompressed SEC1 (65 bytes). `privateKey` is PKCS8 DER. |
| `deriveSessionP256` | `privateKey: Uint8Array`, `publicKey: Uint8Array` | `Promise<SessionAES256GCM>` | Perform ECDH between your private key and the other side's public key, run HKDF-SHA256, and return a `SessionAES256GCM` bound to the derived AES key. `privateKey` is PKCS8 DER, `publicKey` is raw uncompressed SEC1. |

## Go server

Package: `github.com/therealPaulPlay/root-e2ee-protocol/go-server`, package name `rootproto`.

### Struct: `Server`

Constructed via `NewServer` with the following parameters.

| Parameter | Type | Description |
|---|---|---|
| `selfID` | `string` | The server's own ID. Checked against `targetId` on every inbound envelope. |
| `keyStore` | `KeyStore` | Host-populated struct (see below) that owns key persistence. |
| `replayStore` | `ReplayStore` | Host-populated struct (see below) that persists seen requestIDs for replay protection. |

Returns `(*Server, error)`. A `Load` error from the replay store fails construction.

Methods:

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `Close` | — | `error` | Stop the background key-cleanup goroutine. Call once during shutdown. |
| `Receive` | `bytes []byte`, `write WriteFn` | `error` | Entry point for every inbound envelope. |
| `Push` | `clientID, msgType string`, `payload any`, `write WriteFn` | `error` | Server-initiated push to a specific client. Payload is any CBOR-serializable value. |
| `OnRequest` | `msgType string`, `handler RequestHandler` | — | Register the handler for a client-request type. Only one handler per type is allowed, registering twice replaces the prior handler. |
| `OffRequest` | `msgType string` | — | Unregister the handler for a type. |
| `ClearClient` | `clientID string` | `error` | Drop all per-client state (cached session and replay history). Call on unpair so a future re-pairing starts clean and memory is freed. |

Parameter function types:

| Type | Signature | Description |
|---|---|---|
| `WriteFn` | `func(bytes []byte) error` | Host-provided function that writes envelope bytes onto the connection. Called by the library from inside `Receive` and `Push`. |
| `RequestHandler` | `func(clientID string, payload []byte, respond RespondFn) (responsePayload any)` | `payload` is the decrypted, still-CBOR-encoded request body. Return the response, or respond early using `respond(payload)` within the handler in case code needs to be executed after sending the response. |
| `RespondFn` | `func(payload any) error` | Sends the response synchronously from inside the handler. |

### Struct: `KeyStore`

The host populates this struct of function fields and passes it to `NewServer`. The library calls these functions to read and persist key material.

| Field | Signature | Expected behavior |
|---|---|---|
| `GetPrivateKey` | `func(keyType string) *PrivateKey` | Return the server's long-lived private key of the given type, or `nil` if the server has none. One key per type is shared across all clients. |
| `GetClientPublicKey` | `func(clientID string) *PublicKey` | Return the current public key and its type for the named client, or `nil` if the client is unknown. |
| `CommitClientPublicKey` | `func(clientID string, newPublicKey *PublicKey) error` | Persist a client's new public key and its type. |

### Struct: `ReplayStore`

The host implements persistence for seen requestIDs. The library hands opaque bytes and the host writes them durably.

| Field | Signature | Expected behavior |
|---|---|---|
| `Load` | `func() ([]byte, error)` | Return everything the host has persisted, or `nil` on first boot. |
| `Append` | `func(entry []byte) error` | Append a single framed record to durable storage. Any delay between accept and durable save is a replay window on crash. |
| `Save` | `func(snapshot []byte) error` | Replace durable storage with the given snapshot. |

### Struct: `Keypair`

Returned by `GenerateKeypairP256`.

| Field | Type | Description |
|---|---|---|
| `PublicKey` | `[]byte` | The raw public key bytes. |
| `PrivateKey` | `[]byte` | The raw private key bytes. |

### Struct: `PrivateKey`

Returned by the host's `GetPrivateKey`.

| Field | Type | Description |
|---|---|---|
| `Key` | `[]byte` | The raw private key bytes. |
| `KeyType` | `string` | Identifies the key's type. |

### Struct: `PublicKey`

Returned by the host's `GetClientPublicKey` and passed to `CommitClientPublicKey`.

| Field | Type | Description |
|---|---|---|
| `Key` | `[]byte` | The raw public key bytes. |
| `KeyType` | `string` | Identifies the key's type. |

### Struct: `SessionAES256GCM`

Provides AES-256-GCM encryption for use cases outside the request/response flow.

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `Encrypt` | `plaintext, aad []byte` | `([]byte, error)` | Output format is `nonce(12) \|\| ciphertext \|\| tag(16)`. |
| `Decrypt` | `ciphertext, aad []byte` | `([]byte, error)` | Input format matches `Encrypt` output. |

### Functions

| Function | Parameters | Returns | Description |
|---|---|---|---|
| `GenerateKeypairP256` | — | `(*Keypair, error)` | Generate a fresh P-256 keypair. `PublicKey` is raw uncompressed SEC1 (65 bytes), `PrivateKey` is a raw 32-byte scalar. |
| `DeriveSessionP256` | `privateKey, publicKey []byte` | `(*SessionAES256GCM, error)` | Perform ECDH between your private key and the other side's public key, run HKDF-SHA256, and return a `SessionAES256GCM` bound to the derived AES key. |
| `SessionFromKeyAES256GCM` | `key []byte` | `(*SessionAES256GCM, error)` | Construct an AES-256-GCM session from a 32-byte key. |

## Tests

```sh
# JS unit + cross-language e2e (the e2e suite spawns the Go test server over a Unix socket)
cd js-client && npm install && npm test

# Go unit tests
cd go-server && go test ./...
```
