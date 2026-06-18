import { HKDF_INFO, KEY_TYPE_P256 } from "./constants.js";

// P-256 (secp256r1) + HKDF-SHA256 + AES-256-GCM
// Private key: PKCS8 DER bytes (WebCrypto's native format)
// Public key: raw uncompressed SEC1 (65 bytes, leading 0x04)

/**
 * @typedef {Object} Keypair
 * @property {Uint8Array} publicKey  Raw public key bytes
 * @property {Uint8Array} privateKey Raw private key bytes
 */

/** AES-256-GCM session bound to a shared secret */
export class SessionAES256GCM {
	#key;

	/** @param {CryptoKey} cryptoKey */
	constructor(cryptoKey) {
		this.#key = cryptoKey;
	}

	/**
	 * @param {Uint8Array} data
	 * @param {Uint8Array} [aad]
	 * @returns {Promise<Uint8Array>} nonce(12) || ciphertext || tag(16)
	 */
	async encrypt(data, aad) {
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		/** @type {AesGcmParams} */
		const params = { name: "AES-GCM", iv: nonce };
		if (aad) params.additionalData = /** @type {BufferSource} */ (aad);
		const ciphertext = await crypto.subtle.encrypt(params, this.#key, /** @type {BufferSource} */(data));
		const out = new Uint8Array(nonce.length + ciphertext.byteLength);
		out.set(nonce);
		out.set(new Uint8Array(ciphertext), nonce.length);
		return out;
	}

	/**
	 * @param {Uint8Array} bytes nonce(12) || ciphertext || tag(16)
	 * @param {Uint8Array} [aad]
	 * @returns {Promise<Uint8Array>}
	 */
	async decrypt(bytes, aad) {
		/** @type {AesGcmParams} */
		const params = { name: "AES-GCM", iv: bytes.slice(0, 12) };
		if (aad) params.additionalData = /** @type {BufferSource} */ (aad);
		const plaintext = await crypto.subtle.decrypt(params, this.#key, /** @type {BufferSource} */(bytes.slice(12)));
		return new Uint8Array(plaintext);
	}
}

/**
 * Generate a fresh P-256 keypair, public key is raw uncompressed SEC1 (65 bytes), private key is PKCS8 DER
 * @returns {Promise<Keypair>}
 */
export async function generateKeypairP256() {
	const pair = /** @type {CryptoKeyPair} */ (await crypto.subtle.generateKey(
		{ name: "ECDH", namedCurve: "P-256" },
		true,
		["deriveKey", "deriveBits"]
	));
	const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
	const privateKey = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
	return { publicKey, privateKey };
}

/**
 * Derive a session from a private key and the other side's public key based on the key type
 * @param {string} keyType
 * @param {Uint8Array} privateKey
 * @param {Uint8Array} publicKey
 * @returns {Promise<SessionAES256GCM>}
 */
export async function deriveSession(keyType, privateKey, publicKey) {
	switch (keyType) {
		case KEY_TYPE_P256:
			return deriveSessionP256(privateKey, publicKey);
		default:
			throw new Error(`Unknown key type ${keyType}`);
	}
}

/**
 * Derive an AES-GCM session via ECDH from a private key and the other side's public key
 * @param {Uint8Array} privateKey PKCS8 DER
 * @param {Uint8Array} publicKey Raw uncompressed SEC1 (65 bytes)
 * @returns {Promise<SessionAES256GCM>}
 */
export async function deriveSessionP256(privateKey, publicKey) {
	const priv = await crypto.subtle.importKey(
		"pkcs8",
		/** @type {BufferSource} */(privateKey),
		{ name: "ECDH", namedCurve: "P-256" },
		false,
		["deriveBits"]
	);
	const pub = await crypto.subtle.importKey(
		"raw",
		/** @type {BufferSource} */(publicKey),
		{ name: "ECDH", namedCurve: "P-256" },
		false,
		[]
	);

	const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256);
	const hkdfKey = await crypto.subtle.importKey(
		"raw",
		/** @type {BufferSource} */(new Uint8Array(sharedBits)),
		"HKDF",
		false,
		["deriveKey"]
	);

	const aesKey = await crypto.subtle.deriveKey(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: new Uint8Array(0),
			info: new TextEncoder().encode(HKDF_INFO)
		},
		hkdfKey,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"]
	);

	return new SessionAES256GCM(aesKey);
}

/**
 * Compute AES-GCM AAD binding envelope metadata and return as SHA256(type|originId|targetId|requestId)
 * @param {string} msgType
 * @param {string} originId
 * @param {string} targetId
 * @param {string} requestId
 * @returns {Promise<Uint8Array>} 32 bytes
 */
export async function computeAAD(msgType, originId, targetId, requestId) {
	const data = new TextEncoder().encode(`${msgType}|${originId}|${targetId}|${requestId}`);
	const hash = await crypto.subtle.digest("SHA-256", data);
	return new Uint8Array(hash);
}
