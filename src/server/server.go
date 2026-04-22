package rootproto

import (
	"fmt"
	"slices"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// KeyStore is the server's callback seam into host-owned persistence
// The server holds one long-lived private key shared across all clients
type KeyStore struct {
	GetPrivateKey         func() ([]byte, error)                           // raw 32-byte scalar
	GetClientPublicKey    func(clientID string) ([]byte, bool)             // raw uncompressed SEC1, (nil,false) if unknown
	CommitClientPublicKey func(clientID string, newPublicKey []byte) error // persist after validated renewKeyAck
}

// WriteFn is the host-owned wire
type WriteFn func(clientID string, bytes []byte) error

// RequestHandler processes a client request and returns the reply payload
// Payload decrypted, but still-CBOR-encoded; the handler unmarshals into its own types
// Hosts encode app-level results as they see fit; the library does not inspect the shape
type RequestHandler func(clientID string, payload []byte) (replyPayload any)

type Server struct {
	selfID   string
	keyStore KeyStore
	keys     *keyManager
	replay   *replayCache

	sessionMu sync.Mutex
	sessions  map[string]*Session

	handlerMu       sync.RWMutex
	requestHandlers map[string]RequestHandler
}

// NewServer constructs a server
// Close when the host shuts down to stop the background key-cleanup goroutine
func NewServer(selfID string, keyStore KeyStore) *Server {
	return &Server{
		selfID:          selfID,
		keyStore:        keyStore,
		keys:            newKeyManager(),
		replay:          newReplayCache(),
		sessions:        make(map[string]*Session),
		requestHandlers: make(map[string]RequestHandler),
	}
}

// Close stops background goroutines
func (s *Server) Close() error {
	s.keys.close()
	return nil
}

// OnRequest registers the handler for a client-request type
// Only one handler per type; calling OnRequest twice for the same type replaces the prior handler
func (s *Server) OnRequest(msgType string, handler RequestHandler) {
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()
	s.requestHandlers[msgType] = handler
}

// OffRequest unregisters the handler for a type
func (s *Server) OffRequest(msgType string) {
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()
	delete(s.requestHandlers, msgType)
}

// Receive is the entry point for every inbound envelope from the transport layer
// Reserved types are handled internally; app requests are dispatched to the handler
// registered via OnRequest
func (s *Server) Receive(bytes []byte, write WriteFn) error {
	env, err := unmarshalEnvelope(bytes)
	if err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}

	switch env.Type {
	case msgRenewKey:
		return write(env.OriginID, s.handleRenewKey(env))
	case msgRenewKeyAck:
		return write(env.OriginID, s.handleRenewKeyAck(env))
	}

	session, errReply := s.sessionFor(env.OriginID, env.Type, env.RequestID)
	if errReply != nil {
		return write(env.OriginID, errReply)
	}

	aad := computeAAD(env.Type, env.OriginID, env.TargetID)
	plaintext, err := session.Decrypt(env.Payload, aad)
	if err != nil {
		return write(env.OriginID, s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errDecryptionFailed))
	}

	// Reject replays: an authenticated ciphertext with a requestId we've already seen
	if env.RequestID != "" && s.replay.check(env.RequestID) {
		return write(env.OriginID, s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errReplay))
	}

	s.handlerMu.RLock()
	handler, ok := s.requestHandlers[env.Type]
	s.handlerMu.RUnlock()
	if !ok {
		return write(env.OriginID, s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errUnknownType))
	}

	replyPayload := handler(env.OriginID, plaintext)
	replyBytes, err := cbor.Marshal(replyPayload)
	if err != nil {
		return fmt.Errorf("marshal reply payload: %w", err)
	}
	reply, err := s.buildEncryptedReply(env.OriginID, env.Type, replyBytes, env.RequestID, session)
	if err != nil {
		return err
	}
	return write(env.OriginID, reply)
}

// Push encrypts and sends a message not triggered by an incoming request
// RequestID on the wire is empty; clients distinguish pushes from replies by that
func (s *Server) Push(clientID, msgType string, payload any, write WriteFn) error {
	if slices.Contains(reservedTypes, msgType) {
		return fmt.Errorf("reserved message type: %s", msgType)
	}

	session, errReply := s.sessionFor(clientID, msgType, "")
	if errReply != nil {
		return fmt.Errorf("no session for %s", clientID)
	}

	payloadBytes, err := cbor.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	bytes, err := s.buildEncryptedReply(clientID, msgType, payloadBytes, "", session)
	if err != nil {
		return err
	}
	return write(clientID, bytes)
}

// sessionFor returns the cached session for a client, deriving one on cache miss
// Returns (nil, errorReplyBytes) when the client is unknown or key derivation fails
func (s *Server) sessionFor(clientID, msgTypeForError, requestID string) (*Session, []byte) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	if cached, ok := s.sessions[clientID]; ok {
		return cached, nil
	}

	clientPub, ok := s.keyStore.GetClientPublicKey(clientID)
	if !ok {
		return nil, s.buildProtocolError(clientID, requestID, msgTypeForError, errNoClientKey)
	}
	priv, err := s.keyStore.GetPrivateKey()
	if err != nil {
		return nil, s.buildProtocolError(clientID, requestID, msgTypeForError, errInvalidKey)
	}
	secret, err := DeriveSharedSecret(priv, clientPub)
	if err != nil {
		return nil, s.buildProtocolError(clientID, requestID, msgTypeForError, errInvalidKey)
	}
	session, err := SessionFromKey(secret)
	if err != nil {
		return nil, s.buildProtocolError(clientID, requestID, msgTypeForError, errInternalError)
	}
	s.sessions[clientID] = session
	return session, nil
}

func (s *Server) invalidateSession(clientID string) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	delete(s.sessions, clientID)
}

// buildEncryptedReply produces a reply envelope carrying encrypted payload bytes
// Pass nil payload for an empty-body success reply
func (s *Server) buildEncryptedReply(clientID, msgType string, payload []byte, requestID string, session *Session) ([]byte, error) {
	aad := computeAAD(msgType, s.selfID, clientID)
	ciphertext, err := session.Encrypt(payload, aad)
	if err != nil {
		return nil, err
	}
	return marshalEnvelope(envelope{
		Type:      msgType,
		OriginID:  s.selfID,
		TargetID:  clientID,
		RequestID: requestID,
		Payload:   ciphertext,
	})
}

// buildProtocolError produces a plaintext envelope carrying a library-owned error code
func (s *Server) buildProtocolError(clientID, requestID, requestType, code string) []byte {
	out, _ := marshalEnvelope(envelope{
		Type:      requestType,
		OriginID:  s.selfID,
		TargetID:  clientID,
		RequestID: requestID,
		Error:     code,
	})
	return out
}
