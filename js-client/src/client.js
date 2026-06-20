import { Encoder } from "cbor-x";
import { deriveSession, computeAAD, generateKeypairP256 } from "./crypto.js";
import { bytesEqual } from "./utils.js";
import {
	RESERVED_TYPES,
	ERR_DECRYPTION_FAILED,
	ERR_UNSUPPORTED_VERSION,
	ERROR_MESSAGES,
	DEFAULT_REQUEST_TIMEOUT_MS,
	DEFAULT_KEY_MAX_AGE_MS,
	PROTOCOL_VERSION
} from "./constants.js";

// int64AsNumber avoids BigInt values that break Date() and other JS APIs
// The option exists at runtime but is missing from cbor-x's type definitions, hence we need to cast
/** @type {import("cbor-x").Options & { int64AsNumber?: boolean }} */
const cborOptions = { useRecords: false, mapsAsObjects: true, int64AsNumber: true };
const cbor = new Encoder(cborOptions);

/**
 * @typedef {Object} PrivateKey
 * @property {Uint8Array} key
 * @property {string} keyType
 */

/**
 * @typedef {PrivateKey & { createdAt: number }} TimestampedPrivateKey
 */

/**
 * @typedef {Object} PublicKey
 * @property {Uint8Array} key
 * @property {string} keyType
 */

/**
 * @typedef {Object} KeyStore
 * @property {(serverId: string) => Promise<PublicKey | null>} getServerPublicKey
 * @property {(serverId: string) => Promise<TimestampedPrivateKey | null>} getCurrentPrivateKey
 * @property {(serverId: string) => Promise<PrivateKey | null>} getPreviousPrivateKey
 * @property {(serverId: string, newKey: PrivateKey) => Promise<void>} commitNewPrivateKey
 * @property {(serverId: string) => Promise<void>} revertToPreviousPrivateKey
 */

/** @typedef {(bytes: Uint8Array) => void | Promise<void>} WriteFn */

/**
 * Handler for server-initiated pushes
 * On protocol error, payload is null and error is a RelayError
 *
 * @typedef {(payload: any, error: RelayError | null) => void | Promise<void>} PushHandler
 */

/**
 * Thrown when the server rejects a request at the protocol layer
 */
export class RelayError extends Error {
	/** @param {string} code */
	constructor(code) {
		super(ERROR_MESSAGES[code] ?? "No message provided");
		this.name = "RelayError";
		this.code = code;
	}
}

export class Client {
	#selfId;
	#keyStore;
	#sessions = new Map();
	#pending = new Map(); // requestId -> { resolve, reject, timeout }
	/** @type {Map<string, Map<string, PushHandler[]>>} */
	#pushHandlers = new Map(); // serverId -> type -> PushHandler[]
	#renewalPromises = new Map(); // serverId -> Promise (coalesces concurrent renewals)
	#requestTimeoutMs;
	#keyMaxAgeMs;
	#closed = false;

	/**
	 * @param {Object} opts
	 * @param {string} opts.selfId
	 * @param {KeyStore} opts.keyStore
	 * @param {number} [opts.requestTimeoutMs]
	 * @param {number} [opts.keyMaxAgeMs]
	 */
	constructor({ selfId, keyStore, requestTimeoutMs, keyMaxAgeMs }) {
		this.#selfId = selfId;
		this.#keyStore = keyStore;
		this.#requestTimeoutMs = requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
		this.#keyMaxAgeMs = keyMaxAgeMs ?? DEFAULT_KEY_MAX_AGE_MS;
	}

	/**
	 * Register a handler for server-initiated pushes of the given type, scoped to one server (multiple are allowed)
	 * The handler receives (payload, error), on protocol errors, payload is null and error is a RelayError
	 *
	 * @param {string} serverId
	 * @param {string} type
	 * @param {PushHandler} handler
	 */
	onPush(serverId, type, handler) {
		if (this.#closed) throw new Error("Client closed");
		let byType = this.#pushHandlers.get(serverId);
		if (!byType) {
			byType = new Map();
			this.#pushHandlers.set(serverId, byType);
		}
		let list = byType.get(type);
		if (!list) {
			list = [];
			byType.set(type, list);
		}
		list.push(handler);
	}

	/**
	 * @param {string} serverId
	 * @param {string} type
	 * @param {PushHandler} handler
	 */
	offPush(serverId, type, handler) {
		if (this.#closed) throw new Error("Client closed");
		const byType = this.#pushHandlers.get(serverId);
		if (!byType) return;
		const list = byType.get(type);
		if (!list) return;
		const i = list.indexOf(handler);
		if (i >= 0) list.splice(i, 1);
		if (list.length === 0) byType.delete(type);
		if (byType.size === 0) this.#pushHandlers.delete(serverId);
	}

	/**
	 * Send an encrypted request and return the decrypted payload
	 * Triggers a key renewal first if the current key is older than keyMaxAgeMs
	 * On server-reported decryption failure, reverts to the previous key and retries once
	 * Throws {@link RelayError} on protocol-level errors
	 *
	 * @param {string} serverId
	 * @param {string} type
	 * @param {unknown} payload CBOR-serializable
	 * @param {WriteFn} write
	 * @returns {Promise<any>} the decoded plaintext payload
	 */
	async request(serverId, type, payload, write) {
		if (this.#closed) throw new Error("Client closed");
		if (RESERVED_TYPES.includes(type)) throw new Error(`Reserved message type: ${type}`);
		await this.#ensureKeyFresh(serverId, write);
		return this.#exchange(serverId, type, payload, write);
	}

	/**
	 * Entry point for every inbound envelope from the transport layer
	 * Replies to pending requests are resolved internally, everything else is dispatched
	 * to registered push handlers
	 *
	 * @param {Uint8Array} bytes
	 */
	async receive(bytes) {
		if (this.#closed) throw new Error("Client closed");
		let env;
		try {
			env = cbor.decode(bytes);
		} catch (cause) {
			throw new Error("Malformed envelope", { cause });
		}
		if (env.targetId !== this.#selfId) throw new Error("Envelope targetId does not match selfId");

		// Reject on version mismatch
		const result = env.version !== PROTOCOL_VERSION
			? { payload: null, error: ERR_UNSUPPORTED_VERSION }
			: await this.#decodeEnvelope(env, env.originId);

		const pendingRequestId = env.requestId;
		if (pendingRequestId && this.#pending.has(pendingRequestId)) {
			const entry = this.#pending.get(pendingRequestId);
			clearTimeout(entry.timeout);
			this.#pending.delete(pendingRequestId);
			if (result.error) entry.reject(new RelayError(result.error));
			else entry.resolve(result.payload);
			return;
		}

		const byType = this.#pushHandlers.get(env.originId);
		const handlers = byType?.get(env.type);
		if (!handlers) return;

		const error = result.error ? new RelayError(result.error) : null;
		await this.#invoke(handlers, result.payload, error);
	}

	/**
	 * If the current key is older than keyMaxAgeMs, runs a renewal handshake first
	 * Coalesces concurrent calls per serverId so only one renewal runs at a time
	 *
	 * @param {string} serverId
	 * @param {WriteFn} write
	 */
	async #ensureKeyFresh(serverId, write) {
		const current = await this.#keyStore.getCurrentPrivateKey(serverId);
		if (!current) return; // No key — request() will fail when deriving the session
		if (Date.now() - current.createdAt < this.#keyMaxAgeMs) return; // Key still fresh

		// If not already renewing, start renewal
		if (!this.#renewalPromises.has(serverId)) {
			this.#renewalPromises.set(
				serverId,
				this.#renewKey(serverId, write).finally(() => this.#renewalPromises.delete(serverId))
			);
		}
		await this.#renewalPromises.get(serverId);
	}

	/**
	 * @param {string} serverId
	 * @param {WriteFn} write
	 */
	async #renewKey(serverId, write) {
		const current = await this.#keyStore.getCurrentPrivateKey(serverId);
		if (!current) throw new Error(`No current key for server ${serverId}`);

		const newKeypair = await generateKeypairP256();

		// Step 1: renewKey encrypted with OLD session
		await this.#exchange(serverId, "renewKey", { newPublicKey: newKeypair.publicKey }, write);

		// Step 2: current key becomes previous, new becomes current, keyType mustn't change
		await this.#keyStore.commitNewPrivateKey(serverId, { key: newKeypair.privateKey, keyType: current.keyType });

		// Step 3: ACK encrypted with NEW session
		await this.#exchange(serverId, "renewKeyAck", { ack: true }, write);
	}

	/**
	 * Encrypt, send, await the response
	 * On a server-reported DECRYPTION_FAILED, reverts to the previous key and retries once
	 * Resolves with the decoded payload, rejects with {@link RelayError} on protocol errors
	 *
	 * @param {string} serverId
	 * @param {string} type
	 * @param {unknown} payload
	 * @param {WriteFn} write
	 * @returns {Promise<any>}
	 */
	async #exchange(serverId, type, payload, write) {
		try {
			return await this.#roundtrip(serverId, type, payload, write);
		} catch (error) {
			if (!(error instanceof RelayError) || error.code !== ERR_DECRYPTION_FAILED) throw error;

			// Retry with previous encryption if available
			const prev = await this.#keyStore.getPreviousPrivateKey(serverId);
			if (!prev) throw error;

			await this.#keyStore.revertToPreviousPrivateKey(serverId);
			return this.#roundtrip(serverId, type, payload, write);
		}
	}

	/**
	 * Encrypt and write the envelope, register a pending entry keyed by requestId,
	 * and return a Promise resolved by receive() when the matching response arrives
	 *
	 * @param {string} serverId
	 * @param {string} type
	 * @param {unknown} payload
	 * @param {WriteFn} write
	 * @returns {Promise<any>}
	 */
	async #roundtrip(serverId, type, payload, write) {
		const requestId = crypto.randomUUID();
		const session = await this.#sessionFor(serverId);
		const aad = await computeAAD(type, this.#selfId, serverId, requestId);
		const envelope = cbor.encode({
			version: PROTOCOL_VERSION,
			type,
			originId: this.#selfId,
			targetId: serverId,
			requestId,
			payload: await session.encrypt(cbor.encode(payload), aad)
		});

		const responsePromise = new Promise((resolve, reject) => {
			const timeout = setTimeout(() => {
				this.#pending.delete(requestId);
				reject(new Error(`Request ${type} timed out after ${this.#requestTimeoutMs / 1000}s`));
			}, this.#requestTimeoutMs);
			this.#pending.set(requestId, { resolve, reject, timeout });
		});

		try {
			await write(envelope);
		} catch (err) {
			const entry = this.#pending.get(requestId);
			if (entry) {
				clearTimeout(entry.timeout);
				this.#pending.delete(requestId);
			}
			throw err;
		}
		return responsePromise;
	}

	/**
	 * Decrypt and decode a received envelope, trying the previous key if current fails for in-flight responses that still use the previous one
	 *
	 * @param {{type: string, originId: string, targetId: string, requestId: string, payload: Uint8Array, error?: string}} env
	 * @param {string} serverId
	 * @returns {Promise<{ payload: any, error: string | null }>}
	 */
	async #decodeEnvelope(env, serverId) {
		const { type, originId, payload, error } = env;
		if (error) return { payload: null, error }; // Incoming envelope includes protocol-level (unencrypted) error, surface it

		const aad = await computeAAD(type, originId, env.targetId, env.requestId);

		// Try the current key
		try {
			const session = await this.#sessionFor(serverId);
			const plaintext = await session.decrypt(payload, aad);
			return {
				payload: plaintext.length > 0 ? cbor.decode(plaintext) : null,
				error: null
			};
		} catch { }

		// Current session failed, try the previous key
		try {
			const session = await this.#sessionFor(serverId, { usePrevious: true });
			const plaintext = await session.decrypt(payload, aad);
			return {
				payload: plaintext.length > 0 ? cbor.decode(plaintext) : null,
				error: null
			};
		} catch { }

		return { payload: null, error: ERR_DECRYPTION_FAILED };
	}

	/**
	 * Invoke every handler in the list, swallowing errors individually
	 *
	 * @param {PushHandler[]} handlers
	 * @param {any} payload
	 * @param {RelayError | null} error
	 */
	async #invoke(handlers, payload, error) {
		for (const handler of handlers) {
			try { await handler(payload, error); }
			catch (handlerError) { console.error("Handler error:", handlerError); }
		}
	}

	/**
	 * Derive the session from a client's private key and the server's public key
	 * With usePrevious, derives from the previous key (for in-flight responses) and bypasses the cache
	 *
	 * @param {string} serverId
	 * @param {{ usePrevious?: boolean }} [opts]
	 * @returns {Promise<import("./crypto.js").SessionAES256GCM>}
	 */
	async #sessionFor(serverId, { usePrevious = false } = {}) {
		const privateKey = usePrevious
			? await this.#keyStore.getPreviousPrivateKey(serverId)
			: await this.#keyStore.getCurrentPrivateKey(serverId);
		if (!privateKey) throw new Error(`No private key for server ${serverId}`);
		const serverPublicKey = await this.#keyStore.getServerPublicKey(serverId);
		if (!serverPublicKey) throw new Error(`No server public key for server ${serverId}`);
		if (serverPublicKey.keyType !== privateKey.keyType) throw new Error(`Server key type ${serverPublicKey.keyType} does not match client key type ${privateKey.keyType}`);

		if (!usePrevious) {
			// Reuse the cached session only if the key pair (bytes and type) hasn't changed
			const cached = this.#sessions.get(serverId);
			if (cached
				&& cached.privateKey.keyType === privateKey.keyType && bytesEqual(cached.privateKey.key, privateKey.key)
				&& cached.serverPublicKey.keyType === serverPublicKey.keyType && bytesEqual(cached.serverPublicKey.key, serverPublicKey.key)) {
				return cached.session;
			}
		}

		const session = await deriveSession(privateKey.keyType, privateKey.key, serverPublicKey.key);

		// Do not cache the previous session
		if (!usePrevious) {
			this.#sessions.set(serverId, {
				session,
				privateKey,
				serverPublicKey
			});
		}

		return session;
	}

	/**
	 * Release all client state
	 * Reject pending requests, clear push handlers, and drop cached sessions
	 */
	close() {
		if (this.#closed) return;
		this.#closed = true;
		for (const entry of this.#pending.values()) {
			clearTimeout(entry.timeout);
			entry.reject(new Error("Client closed"));
		}
		this.#pending.clear();
		this.#pushHandlers.clear();
		this.#sessions.clear();
		this.#renewalPromises.clear();
	}
}
