package rootproto

// Reserved message types owned by the key renewal protocol
const (
	msgRenewKey    = "renewKey"
	msgRenewKeyAck = "renewKeyAck"
)

// Types the kernel handles internally, hosts must not send these via Push
var reservedTypes = []string{msgRenewKey, msgRenewKeyAck}

// protocolVersion is the protocol version stamped on every envelope
const protocolVersion uint64 = 1

// Protocol error codes emitted on the wire
const (
	errDecryptionFailed   = "DECRYPTION_FAILED"
	errNoClientKey        = "NO_CLIENT_KEY"
	errInvalidKey         = "INVALID_KEY"
	errInvalidPayload     = "INVALID_PAYLOAD"
	errInternalError      = "INTERNAL_ERROR"
	errUnknownType        = "UNKNOWN_TYPE"
	errReplay             = "REPLAY"
	errUnsupportedVersion = "UNSUPPORTED_VERSION"
	errUnsupportedKeyType = "UNSUPPORTED_KEY_TYPE"
)
