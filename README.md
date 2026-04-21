# ROOT (Protocol)

End-to-end encrypted communication protocol with two parts: A JS client package, and a Go server package. Uses CBOR for serialization and comes with a built-in key-renewal system for forward secrecy.

## Install

```sh
# JS
npm install root-e2ee-protocol

# Go
go get github.com/therealPaulPlay/root-e2ee-protocol/src/server
```

## Model

- Key ownership: The server has one long-lived private key shared across all clients. Each client has one private key per server it talks to.
- Key renewal: Only the client initiates renewal. The server is reactive.
- Reply expectations: Clients always get a reply to a request, while servers can push messages without expecting anything back.
- Ordering: Requests do not guarantee arrival order. If you fire multiple requests without awaiting, they run in parallel and resolve as their replies arrive (and not in the order you sent them). Use `await` before the next request if you need them handled in sequence. Push handlers fire whenever a push arrives and may interleave with requests. Do not assume a push has been handled just because a later request has resolved.

## JS client

Package: `root-e2ee-protocol`.

### Class: `Client`

Constructor accepts a single object with the following properties.

| Property | Type | Description |
|---|---|---|
| `selfId` | `string` | The client's own ID. Sent as `originId` on every outbound envelope. |
| `keyStore` | `KeyStore` | Host-implemented object (see below) that owns key persistence. |
| `requestTimeoutMs` | `number?` | How long `request` waits for a matching reply before rejecting. Default `10000`. |
| `keyMaxAgeMs` | `number?` | When the current key's `createdAt` is older than this, `request` runs a renewal handshake before sending. Default `300000`. |

Methods:

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `request` | `serverId: string`, `type: string`, `payload: any`, `write: WriteFn` | `Promise<DecodedMessage>` | Encrypt and send a request, resolve when the server's reply arrives. |
| `receive` | `bytes: Uint8Array` | `void` | Entry point for every inbound envelope. Host needs to call this for each message off the wire.|
| `onPush` | `type: string`, `handler: PushHandler` | `void` | Register a push handler for a specific message type. Multiple handlers per type are supported and fire in registration order. |
| `offPush` | `type: string`, `handler: PushHandler` | `void` | Remove a previously-registered push handler. |
| `onError` | `handler: ErrorHandler` | `void` | Register an error handler. Multiple handlers are supported and fire in registration order. |
| `offError` | `handler: ErrorHandler` | `void` | Remove a previously-registered error handler. |


Parameter function types:

| Type | Signature | Description |
|---|---|---|
| `WriteFn` | `(bytes: Uint8Array) => void` | Host-provided function that writes envelope bytes onto the wire. Called by the library from inside `request`. |
| `PushHandler` | `(msg: DecodedMessage) => void \| Promise<void>` | Registered via `onPush`, fires for server-initiated messages of a given type. |
| `ErrorHandler` | `(msg: DecodedMessage) => void \| Promise<void>` | Registered via `onError`, fires for protocol-level errors on inbound messages. |

### Type: `KeyStore`

The host implements this interface and passes an instance to the `Client` constructor. The library calls these methods to read and persist key material during requests and renewals. All private keys are PKCS8 DER bytes; all public keys are raw uncompressed SEC1 (65 bytes, leading `0x04`).

| Method | Parameters | Returns | Expected behavior |
|---|---|---|---|
| `getCurrent` | `serverId: string` | `Promise<{ privateKey: Uint8Array, serverPublicKey: Uint8Array, createdAt: number } \| null>` | Return the client's current private key for this server, the server's current public key, and the epoch ms the pair was installed. Return `null` if no key is stored. |
| `getPrevious` | `serverId: string` | `Promise<{ privateKey: Uint8Array, serverPublicKey: Uint8Array } \| null>` | Return the pair that was current immediately before the most recent renewal, or `null` if none is retained. The library falls back to this pair when decryption under the current pair fails. |
| `commitNewKey` | `serverId: string`, `newPrivateKey: Uint8Array`, `serverPublicKey: Uint8Array` | `Promise<void>` | Atomically move the current pair into previous and install `(newPrivateKey, serverPublicKey)` as the new current, with `createdAt` set to now. Called by the library at the end of a successful renewal. |
| `revertToPrevious` | `serverId: string` | `Promise<void>` | Swap previous into current and clear previous. Called when the server reports `DECRYPTION_FAILED`, indicating the two sides fell out of sync during a prior renewal. |

### Type: `DecodedMessage`

Returned from `request` and passed to push and error handlers.

| Field | Type | Description |
|---|---|---|
| `type` | `string` | Message type from the envelope. |
| `originId` | `string` | Sender's ID. |
| `payload` | `any \| null` | Decoded plaintext, or `null` when the envelope carried a protocol error. |
| `error` | `string \| null` | Protocol error code (see "Constants" below), or `null` on success. |

### Class: `Session`

Returned by `deriveSession`. Provides AES-256-GCM encryption for use cases outside the request/response flow.

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `encrypt` | `data: Uint8Array`, `aad?: Uint8Array` | `Promise<Uint8Array>` | Encrypt `data`. Output format is `nonce(12) \|\| ciphertext \|\| tag(16)`. `aad` is optional additional authenticated data. |
| `decrypt` | `bytes: Uint8Array`, `aad?: Uint8Array` | `Promise<Uint8Array>` | Decrypt bytes produced by `encrypt`. `aad` must match whatever was passed to `encrypt`. |

### Functions

| Function | Parameters | Returns | Description |
|---|---|---|---|
| `generateKeypair` | — | `Promise<{ publicKey: Uint8Array, privateKey: Uint8Array }>` | Generate a fresh P-256 keypair. `publicKey` is raw uncompressed SEC1 (65 bytes). `privateKey` is PKCS8 DER. |
| `deriveSession` | `privateKey: Uint8Array`, `publicKey: Uint8Array` | `Promise<Session>` | Perform ECDH between your private key and the other side's public key, run HKDF-SHA256, and return a `Session` bound to the derived AES key. `privateKey` is PKCS8 DER, `publicKey` is raw uncompressed SEC1. |

### Constants

| Name | Value | Description |
|---|---|---|
| `ERR_DECRYPTION_FAILED` | `"DECRYPTION_FAILED"` | Canonical code used when decryption fails. Compare `DecodedMessage.error` against this. |

## Go server

Package: `github.com/therealPaulPlay/root-e2ee-protocol/src/server`, package name `rootproto`.

### Struct: `Server`

Constructor: `NewServer(selfID string, keyStore KeyStore) *Server`.

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `Close` | — | `error` | Stop the background key-cleanup goroutine. Call once during shutdown. |
| `Receive` | `bytes []byte`, `write WriteFn` | `error` | Entry point for every inbound envelope. |
| `Push` | `clientID, msgType string`, `payload any`, `write WriteFn` | `error` | Server-initiated push to a specific client. Payload is any CBOR-serializable value. |
| `OnRequest` | `msgType string`, `handler RequestHandler` | — | Register the handler for a client-request type. Only one handler per type; calling this twice for the same type replaces the prior handler. |
| `OffRequest` | `msgType string` | — | Unregister the handler for a type. |
| `OnError` | `handler ErrorHandler` | — | Register an error handler. Multiple handlers are supported and fire in registration order. |
| `OffError` | `handler ErrorHandler` | — | Unregister a previously-added error handler (compared by function pointer identity). |

Parameter function types:

| Type | Signature | Description |
|---|---|---|
| `WriteFn` | `func(clientID string, bytes []byte) error` | Host-provided function that writes envelope bytes onto the connection associated with `clientID`. Called by the library from inside `Receive` and `Push`. |
| `RequestHandler` | `func(msg IncomingMessage) (replyPayload any)` | The return value is CBOR-encoded and encrypted as the reply. Hosts encode app-level errors into `replyPayload` themselves; the library does not inspect the shape. |
| `ErrorHandler` | `func(msg IncomingMessage, err error)` | Called for protocol-level failures on inbound messages (decryption failed, unknown type, etc). |

### Struct: `KeyStore`

**The host populates this struct of function fields** and passes it to `NewServer`. The library calls these functions to read and persist key material. All private keys are raw 32-byte scalars; all public keys are raw uncompressed SEC1 (65 bytes).

| Field | Signature | Expected behavior |
|---|---|---|
| `GetPrivateKey` | `func() ([]byte, error)` | Return the server's long-lived private key. One key is shared across all clients. |
| `GetClientPublicKey` | `func(clientID string) ([]byte, bool)` | Return the current public key for the named client. Return `(nil, false)` if the client is unknown. |
| `CommitClientPublicKey` | `func(clientID string, newPublicKey []byte) error` | Persist a client's new public key. Called by the library when a `renewKeyAck` validates successfully. |

### Struct: `IncomingMessage`

Passed to a `RequestHandler`.

| Field | Type | Description |
|---|---|---|
| `Type` | `string` | Client's request type. |
| `ClientID` | `string` | Originating client. |
| `Payload` | `[]byte` | Decrypted plaintext, still CBOR-encoded. The handler calls `cbor.Unmarshal(msg.Payload, &dst)` into its own typed struct. The client side exposes payloads as already-decoded `any` because JS handles dynamic shapes natively; Go handlers benefit from unmarshalling into concrete types themselves. |

### Struct: `Keypair`

Returned by `GenerateKeypair`.

| Field | Type | Description |
|---|---|---|
| `PublicKey` | `[]byte` | Raw uncompressed SEC1 (65 bytes). |
| `PrivateKey` | `[]byte` | Raw 32-byte scalar. |

### Struct: `Session`

Returned by `SessionFromKey`. Provides AES-256-GCM encryption for use cases outside the request/response flow.

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `Encrypt` | `plaintext, aad []byte` | `([]byte, error)` | Output format is `nonce(12) \|\| ciphertext \|\| tag(16)`. |
| `Decrypt` | `ciphertext, aad []byte` | `([]byte, error)` | Input format matches `Encrypt` output. |

### Functions

| Function | Parameters | Returns | Description |
|---|---|---|---|
| `GenerateKeypair` | — | `(*Keypair, error)` | Generate a fresh P-256 keypair (raw bytes). |
| `DeriveSharedSecret` | `privateKey, publicKey []byte` | `([]byte, error)` | ECDH followed by HKDF-SHA256. Returns a 32-byte AES key. |
| `SessionFromKey` | `key []byte` | `(*Session, error)` | Construct an AES-GCM session from a 32-byte key. |

### Constants

| Name | Value | Description |
|---|---|---|
| `ErrDecryptionFailed` | `"DECRYPTION_FAILED"` | Set on an error envelope when the server cannot decrypt a received message. |
| `ErrNoClientKey` | `"NO_CLIENT_KEY"` | Set when `GetClientPublicKey` returns `(nil, false)`. |
| `ErrInvalidKey` | `"INVALID_KEY"` | Set when key parsing or ECDH derivation fails on the server side. |
| `ErrInvalidPayload` | `"INVALID_PAYLOAD"` | Set when a reserved-type payload cannot be decoded. |
| `ErrInternalError` | `"INTERNAL_ERROR"` | Catch-all for server-side failures that should not happen. |
| `ErrUnknownType` | `"UNKNOWN_TYPE"` | Set when no handler is registered for the requested type. |

## Tests

```sh
# JS unit + cross-language e2e (the e2e suite spawns the Go test server over a Unix socket)
cd src/client && npm install && npm test

# Go unit tests
cd src/server && go test ./...
```
