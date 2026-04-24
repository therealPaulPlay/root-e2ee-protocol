package rootproto

import (
	"bytes"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

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
type WriteFn func(bytes []byte) error

// RespondFn sends the response synchronously from inside the handler
type RespondFn func(payload any) error

// RequestHandler processes a client request
// Either return the response payload, or call respond() to send it immediately (return value will be ignored)
type RequestHandler func(clientID string, payload []byte, respond RespondFn) (responsePayload any)

type Server struct {
	selfID   string
	keyStore KeyStore
	replay   *replayTracker
	keys     *keyManager

	sessionMu sync.Mutex
	sessions  map[string]*cachedSession

	handlerMu       sync.RWMutex
	requestHandlers map[string]RequestHandler

	closeOnce sync.Once
	closed    atomic.Bool
}

// cachedSession pairs a derived session with the key material that produced it
// so sessionFor can detect and prune on key changes
type cachedSession struct {
	session         *Session
	privateKey      []byte
	clientPublicKey []byte
}

// NewServer constructs a server
// Close when the host shuts down to stop the background key-cleanup goroutine
func NewServer(selfID string, keyStore KeyStore, replayStore ReplayStore) (*Server, error) {
	replay, err := newReplayTracker(replayStore)
	if err != nil {
		return nil, fmt.Errorf("load replay state: %w", err)
	}
	return &Server{
		selfID:          selfID,
		keyStore:        keyStore,
		replay:          replay,
		keys:            newKeyManager(),
		sessions:        make(map[string]*cachedSession),
		requestHandlers: make(map[string]RequestHandler),
	}, nil
}

// OnRequest registers the handler for a client-request type
// Only one handler per type; calling OnRequest twice for the same type replaces the prior handler
func (s *Server) OnRequest(msgType string, handler RequestHandler) error {
	if s.closed.Load() {
		return fmt.Errorf("server closed")
	}
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()
	s.requestHandlers[msgType] = handler
	return nil
}

// OffRequest unregisters the handler for a type
func (s *Server) OffRequest(msgType string) error {
	if s.closed.Load() {
		return fmt.Errorf("server closed")
	}
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()
	delete(s.requestHandlers, msgType)
	return nil
}

// ClearClient drops all per-client state (cached session and replay history)
func (s *Server) ClearClient(clientID string) error {
	s.sessionMu.Lock()
	delete(s.sessions, clientID)
	s.sessionMu.Unlock()
	return s.replay.deleteClient(clientID)
}

// Receive is the entry point for every inbound envelope from the transport layer
// Reserved types are handled internally; app requests are dispatched to the handler
// registered via OnRequest
func (s *Server) Receive(bytes []byte, write WriteFn) error {
	if s.closed.Load() {
		return fmt.Errorf("server closed")
	}
	env, err := unmarshalEnvelope(bytes)
	if err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if env.TargetID != s.selfID {
		return fmt.Errorf("envelope targetId does not match selfID")
	}

	switch env.Type {
	case msgRenewKey:
		return write(s.handleRenewKey(env))
	case msgRenewKeyAck:
		return write(s.handleRenewKeyAck(env))
	}

	session, errorCode := s.sessionFor(env.OriginID)
	if errorCode != "" {
		return write(s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errorCode))
	}

	aad := computeAAD(env.Type, env.OriginID, env.TargetID)
	plaintext, err := session.Decrypt(env.Payload, aad)
	if err != nil {
		return write(s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errDecryptionFailed))
	}

	// Reject replays: an authenticated ciphertext with a requestId we've already seen
	if env.RequestID != "" {
		seen, err := s.replay.checkAndRecord(env.OriginID, env.RequestID)
		if err != nil {
			return write(s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errInternalError))
		}
		if seen {
			return write(s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errReplay))
		}
	}

	s.handlerMu.RLock()
	handler, ok := s.requestHandlers[env.Type]
	s.handlerMu.RUnlock()
	if !ok {
		return write(s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errUnknownType))
	}

	responded := false
	respond := func(payload any) error {
		if responded {
			return fmt.Errorf("already sent response")
		}
		responded = true
		return s.sendResponse(env, payload, session, write)
	}

	returnValue := handler(env.OriginID, plaintext, respond)
	if responded {
		return nil
	}
	return s.sendResponse(env, returnValue, session, write)
}

// sendResponse CBOR-encodes the payload, encrypts it under the given session, and writes the envelope
func (s *Server) sendResponse(env envelope, payload any, session *Session, write WriteFn) error {
	payloadBytes, err := cbor.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal response payload: %w", err)
	}
	response, err := s.buildEncryptedResponse(env.OriginID, env.Type, payloadBytes, env.RequestID, session)
	if err != nil {
		return err
	}
	return write(response)
}

// Push encrypts and sends a message not triggered by an incoming request
// RequestID on the wire is empty; clients distinguish pushes from replies by that
func (s *Server) Push(clientID, msgType string, payload any, write WriteFn) error {
	if s.closed.Load() {
		return fmt.Errorf("server closed")
	}
	if slices.Contains(reservedTypes, msgType) {
		return fmt.Errorf("reserved message type: %s", msgType)
	}

	session, errorCode := s.sessionFor(clientID)
	if errorCode != "" {
		return fmt.Errorf("no session for %s: %s", clientID, errorCode)
	}

	payloadBytes, err := cbor.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	bytes, err := s.buildEncryptedResponse(clientID, msgType, payloadBytes, "", session)
	if err != nil {
		return err
	}
	return write(bytes)
}

// sessionFor returns the cached session for a client, deriving a fresh one when the
// cached entry's keys no longer match the KeyStore
func (s *Server) sessionFor(clientID string) (*Session, string) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	clientPub, ok := s.keyStore.GetClientPublicKey(clientID)
	if !ok {
		return nil, errNoClientKey
	}
	priv, err := s.keyStore.GetPrivateKey()
	if err != nil {
		return nil, errInvalidKey
	}

	// Reuse the cached session only if the key pair hasn't changed
	if cached, ok := s.sessions[clientID]; ok && bytes.Equal(cached.privateKey, priv) && bytes.Equal(cached.clientPublicKey, clientPub) {
		return cached.session, ""
	}

	secret, err := deriveSharedSecret(priv, clientPub)
	if err != nil {
		return nil, errInvalidKey
	}
	session, err := SessionFromKey(secret)
	if err != nil {
		return nil, errInternalError
	}
	s.sessions[clientID] = &cachedSession{
		session:         session,
		privateKey:      append([]byte(nil), priv...),
		clientPublicKey: append([]byte(nil), clientPub...),
	}
	return session, ""
}

// buildEncryptedResponse produces a response envelope carrying encrypted payload bytes
// Pass nil payload for an empty-body success response
func (s *Server) buildEncryptedResponse(clientID, msgType string, payload []byte, requestID string, session *Session) ([]byte, error) {
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

// Close stops background goroutines and releases per-client state
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.keys.close()
		s.sessionMu.Lock()
		s.sessions = make(map[string]*cachedSession)
		s.sessionMu.Unlock()
		s.handlerMu.Lock()
		s.requestHandlers = make(map[string]RequestHandler)
		s.handlerMu.Unlock()
	})
	return nil
}
