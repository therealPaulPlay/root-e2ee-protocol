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

// IncomingMessage is the decoded, decrypted result handed to a request handler
// Payload is still CBOR-encoded; the handler unmarshals it into its own types
type IncomingMessage struct {
	Type     string
	ClientID string
	Payload  []byte
}

// RequestHandler processes a client request and returns the reply payload
// Hosts encode app-level results as they see fit; the library does not inspect the shape
type RequestHandler func(msg IncomingMessage) (replyPayload any)

// ErrorHandler is called for protocol-level errors on inbound messages
type ErrorHandler func(msg IncomingMessage, err error)

type registeredErrorHandler struct {
	id      uint64
	handler ErrorHandler
}

type Server struct {
	selfID   string
	keyStore KeyStore
	keys     *keyManager
	replay   *replayCache

	sessionMu sync.Mutex
	sessions  map[string]*Session

	handlerMu        sync.RWMutex
	requestHandlers  map[string]RequestHandler
	errorHandlers    []registeredErrorHandler
	nextErrHandlerID uint64
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

// OnError registers a handler for protocol-level errors on inbound messages
// Returns an ID the host passes to OffError to unregister the handler
// Multiple handlers are supported and fire in registration order
func (s *Server) OnError(handler ErrorHandler) uint64 {
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()
	s.nextErrHandlerID++
	id := s.nextErrHandlerID
	s.errorHandlers = append(s.errorHandlers, registeredErrorHandler{id, handler})
	return id
}

// OffError unregisters a previously-added error handler by its ID
func (s *Server) OffError(id uint64) {
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()
	for i, h := range s.errorHandlers {
		if h.id == id {
			s.errorHandlers = append(s.errorHandlers[:i], s.errorHandlers[i+1:]...)
			return
		}
	}
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
		s.invokeError(IncomingMessage{Type: env.Type, ClientID: env.OriginID}, err)
		return write(env.OriginID, s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrDecryptionFailed))
	}

	// Reject replays: an authenticated ciphertext with a requestId we've already seen
	if env.RequestID != "" && s.replay.check(env.RequestID) {
		return write(env.OriginID, s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrReplay))
	}

	msg := IncomingMessage{Type: env.Type, ClientID: env.OriginID, Payload: plaintext}

	s.handlerMu.RLock()
	handler, ok := s.requestHandlers[env.Type]
	s.handlerMu.RUnlock()
	if !ok {
		s.invokeError(msg, fmt.Errorf("no handler registered for type %s", env.Type))
		return write(env.OriginID, s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrUnknownType))
	}

	replyPayload := handler(msg)
	replyBytes, err := cbor.Marshal(replyPayload)
	if err != nil {
		return fmt.Errorf("marshal reply payload: %w", err)
	}
	reply, err := s.buildEncryptedReply(env.OriginID, env.Type+resultSuffix, replyBytes, env.RequestID, session)
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
		return nil, s.buildProtocolError(clientID, requestID, msgTypeForError, ErrNoClientKey)
	}
	priv, err := s.keyStore.GetPrivateKey()
	if err != nil {
		return nil, s.buildProtocolError(clientID, requestID, msgTypeForError, ErrInvalidKey)
	}
	secret, err := DeriveSharedSecret(priv, clientPub)
	if err != nil {
		return nil, s.buildProtocolError(clientID, requestID, msgTypeForError, ErrInvalidKey)
	}
	session, err := SessionFromKey(secret)
	if err != nil {
		return nil, s.buildProtocolError(clientID, requestID, msgTypeForError, ErrInternalError)
	}
	s.sessions[clientID] = session
	return session, nil
}

func (s *Server) invalidateSession(clientID string) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	delete(s.sessions, clientID)
}

func (s *Server) invokeError(msg IncomingMessage, err error) {
	s.handlerMu.RLock()
	// Snapshot so we release the lock before calling user code
	snapshot := make([]registeredErrorHandler, len(s.errorHandlers))
	copy(snapshot, s.errorHandlers)
	s.handlerMu.RUnlock()
	for _, h := range snapshot {
		h.handler(msg, err)
	}
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
		Type:      requestType + resultSuffix,
		OriginID:  s.selfID,
		TargetID:  clientID,
		RequestID: requestID,
		Error:     code,
	})
	return out
}
