export const RESERVED_TYPES = ["renewKey", "renewKeyAck"];
export const ERR_DECRYPTION_FAILED = "DECRYPTION_FAILED";
export const ERR_UNKNOWN_TYPE = "UNKNOWN_TYPE";

export const HKDF_INFO = "root-privacy-encryption";
export const RESULT_SUFFIX = "Result";

export const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
export const DEFAULT_KEY_MAX_AGE_MS = 5 * 60_000;

// Concise human-readable messages for protocol error codes, attached to RelayError.message
/** @type {Record<string, string>} */
export const ERROR_MESSAGES = {
	DECRYPTION_FAILED: "Server failed to decrypt the request",
	NO_CLIENT_KEY: "Server is missing key for this client",
	INVALID_KEY: "Server rejected the key as malformed",
	INVALID_PAYLOAD: "Server rejected the payload as malformed",
	INTERNAL_ERROR: "Server encountered an internal error",
	UNKNOWN_TYPE: "Server does not recognize the request type",
	REPLAY: "Server rejected the request as a replay"
};
