package rootproto

// Reserved message types owned by the key renewal protocol
const (
	MsgRenewKey    = "renewKey"
	MsgRenewKeyAck = "renewKeyAck"
)

// ReservedTypes lists all types the kernel handles internally
var ReservedTypes = []string{MsgRenewKey, MsgRenewKeyAck}

// Response type suffix convention
// A request of type X gets a response of type X + ResultSuffix
const ResultSuffix = "Result"

// Canonical error codes emitted by the library
const (
	ErrDecryptionFailed = "DECRYPTION_FAILED"
	ErrNoClientKey      = "NO_CLIENT_KEY"
	ErrInvalidKey       = "INVALID_KEY"
	ErrInvalidPayload   = "INVALID_PAYLOAD"
	ErrInternalError    = "INTERNAL_ERROR"
	ErrUnknownType      = "UNKNOWN_TYPE"
)