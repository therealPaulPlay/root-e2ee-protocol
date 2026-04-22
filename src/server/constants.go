package rootproto

// Reserved message types owned by the key renewal protocol
const (
	msgRenewKey    = "renewKey"
	msgRenewKeyAck = "renewKeyAck"
)

// Types the kernel handles internally, hosts must not send these via Push
var reservedTypes = []string{msgRenewKey, msgRenewKeyAck}

// A request of type X gets a response of type X + resultSuffix
const resultSuffix = "Result"

// Canonical error codes emitted by the library
const (
	ErrDecryptionFailed = "DECRYPTION_FAILED"
	ErrNoClientKey      = "NO_CLIENT_KEY"
	ErrInvalidKey       = "INVALID_KEY"
	ErrInvalidPayload   = "INVALID_PAYLOAD"
	ErrInternalError    = "INTERNAL_ERROR"
	ErrUnknownType      = "UNKNOWN_TYPE"
	ErrReplay           = "REPLAY"
)