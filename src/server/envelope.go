package rootproto

import "github.com/fxamacker/cbor/v2"

// envelope is the internal CBOR wire format
type envelope struct {
	Type      string `cbor:"type"`
	OriginID  string `cbor:"originId"`
	TargetID  string `cbor:"targetId"`
	RequestID string `cbor:"requestId"`
	Payload   []byte `cbor:"payload,omitempty"` // encrypted app content; nil on protocol errors
	Error     string `cbor:"error,omitempty"`   // library-owned error code
}

func marshalEnvelope(m envelope) ([]byte, error) {
	return cbor.Marshal(m)
}

func unmarshalEnvelope(b []byte) (envelope, error) {
	var m envelope
	err := cbor.Unmarshal(b, &m)
	return m, err
}