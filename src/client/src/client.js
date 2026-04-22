import { deriveSession, computeAAD, generateKeypair } from "./crypto.js";
import { cbor } from "./envelope.js";
import {
	RESERVED_TYPES,
	ERR_DECRYPTION_FAILED,
	ERROR_MESSAGES,
	DEFAULT_REQUEST_TIMEOUT_MS,
	DEFAULT_KEY_MAX_AGE_MS
} from "./constants.js";

/**
 * @typedef {Object} CurrentKeyCombination
 * @property {Uint8Array} privateKey PKCS8 DER
 * @property {Uint8Array} serverPublicKey Raw uncompressed SEC1 (65 bytes)
 * @property {number} createdAt
 */

/**
 * @typedef {Object} PreviousKeyCombination
 * @property {Uint8Array} privateKey PKCS8 DER
 * @property {Uint8Array} serverPublicKey Raw uncompressed SEC1 (65 bytes)
 */

/**
 * @typedef {Object} KeyStore
 * @property {(serverId: string) => Promise<CurrentKeyCombination | null>} getCurrent
 * @property {(serverId: string) => Promise<PreviousKeyCombination | null>} getPrevious
 * @property {(serverId: string, newPrivateKey: Uint8Array) => Promise<void>} commitNewKey
 * @property {(serverId: string) => Promise<void>} revertToPrevious
 */

/** @typedef {(bytes: Uint8Array) => void} WriteFn */

/**
 * Handler for server-initiated pushes
 * On protocol error, payload is null and error is a RelayError
 *
 * @typedef {(payload: any, error: RelayError | null) => void | Promise<void>} PushHandler
 */

/**
 * Thrown when the server rejects a request at the protocol layer
 * code holds the protocol error code; message holds a concise human-readable description
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
	 * Register a handler for server-initiated pushes of the given type, scoped to one server
	 * Multiple handlers per (serverId, type) fire in registration order
	 * The handler receives (payload, error): on protocol errors, payload is null and error is a RelayError
	 *
	 * @param {string} serverId
	 * @param {string} type
	 * @param {PushHandler} handler
	 */
	onPush(serverId, type, handler) {
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
		if (RESERVED_TYPES.includes(type)) throw new Error(`Reserved message type: ${type}`);
		await this.#ensureKeyFresh(serverId, write);
		return this.#exchange(serverId, type, payload, write, true);
	}

	/**
	 * Entry point for every inbound envelope from the transport layer
	 * Replies to pending requests are resolved internally; everything else is dispatched
	 * to registered push handlers
	 *
	 * @param {Uint8Array} bytes
	 */
	async receive(bytes) {
		const env = cbor.decode(bytes);
		const result = await this.#decodeEnvelope(env, env.originId);

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
		const current = await this.#keyStore.getCurrent(serverId);
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
		const current = await this.#keyStore.getCurrent(serverId);
		if (!current) throw new Error(`No current key for server ${serverId}`);

		const newKeypair = await generateKeypair();

		// Step 1: renewKey encrypted with OLD session. No retry fallback — a decryption error
		// here would incorrectly rotate into the previous key
		await this.#exchange(
			serverId, "renewKey", { newPublicKey: newKeypair.publicKey }, write, false
		);

		// Step 2: current key becomes previous, new becomes current
		await this.#keyStore.commitNewKey(serverId, newKeypair.privateKey);
		this.#sessions.delete(serverId);

		// Step 3: ACK encrypted with NEW session. Non-fatal if the reply is lost;
		// client keeps the previous key stored, and reverts to it on mismatch
		try {
			await this.#exchange(serverId, "renewKeyAck", { ack: true }, write, false);
		} catch { }
	}

	/**
	 * Encrypt, send, await the reply
	 * If retryOnServerDecryptionFailure is true and the server reports DECRYPTION_FAILED,
	 * reverts to the previous key and runs one additional exchange
	 * Resolves with the decoded payload, rejects with {@link RelayError} on protocol errors
	 *
	 * @param {string} serverId
	 * @param {string} type
	 * @param {unknown} payload
	 * @param {WriteFn} write
	 * @param {boolean} retryOnServerDecryptionFailure
	 * @returns {Promise<any>}
	 */
	async #exchange(serverId, type, payload, write, retryOnServerDecryptionFailure) {
		try {
			return await this.#roundtrip(serverId, type, payload, write);
		} catch (error) {
			if (!retryOnServerDecryptionFailure) throw error;
			if (!(error instanceof RelayError) || error.code !== ERR_DECRYPTION_FAILED) throw error;

			// Retry with previous encryption if available
			const prev = await this.#keyStore.getPrevious(serverId);
			if (!prev) throw error;

			await this.#keyStore.revertToPrevious(serverId);
			this.#sessions.delete(serverId);
			return this.#roundtrip(serverId, type, payload, write);
		}
	}

	/**
	 * Encrypt and write the envelope, register a pending entry keyed by requestId,
	 * and return a Promise resolved by receive() when the matching reply arrives
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
		const aad = await computeAAD(type, this.#selfId, serverId);
		const envelope = cbor.encode({
			type,
			originId: this.#selfId,
			targetId: serverId,
			requestId,
			payload: await session.encrypt(cbor.encode(payload), aad)
		});

		const reply = new Promise((resolve, reject) => {
			const timeout = setTimeout(() => {
				this.#pending.delete(requestId);
				reject(new Error(`Request ${type} timed out after ${this.#requestTimeoutMs}ms`));
			}, this.#requestTimeoutMs);
			this.#pending.set(requestId, { resolve, reject, timeout });
		});

		write(envelope);
		return reply;
	}

	/**
	 * Decrypt and decode a received envelope, trying the previous key if current fails
	 *
	 * @param {{type: string, originId: string, targetId: string, requestId: string, payload: Uint8Array, error?: string}} env
	 * @param {string} serverId
	 * @returns {Promise<{ payload: any, error: string | null }>}
	 */
	async #decodeEnvelope(env, serverId) {
		const { type, originId, payload, error } = env;

		// Incoming envelope includes protocol-level (unencrypted) error, surface it
		if (error) return { payload: null, error };

		const aad = await computeAAD(type, originId, env.targetId);

		const session = await this.#sessionFor(serverId).catch(() => null);
		if (session) {
			try {
				const plaintext = await session.decrypt(payload, aad);
				return {
					payload: plaintext.length > 0 ? cbor.decode(plaintext) : null,
					error: null
				};
			} catch { }
		}

		const prev = await this.#keyStore.getPrevious(serverId);
		if (prev) {
			try {
				const prevSession = await deriveSession(prev.privateKey, prev.serverPublicKey);
				const plaintext = await prevSession.decrypt(payload, aad);
				return {
					payload: plaintext.length > 0 ? cbor.decode(plaintext) : null,
					error: null
				};
			} catch { }
		}

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
	 * @param {string} serverId
	 * @returns {Promise<import("./crypto.js").Session>}
	 */
	async #sessionFor(serverId) {
		const cached = this.#sessions.get(serverId);
		if (cached) return cached;
		const current = await this.#keyStore.getCurrent(serverId);
		if (!current) throw new Error(`No current key for server ${serverId}`);
		const session = await deriveSession(current.privateKey, current.serverPublicKey);
		this.#sessions.set(serverId, session);
		return session;
	}
}
