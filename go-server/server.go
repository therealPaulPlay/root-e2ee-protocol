package rootproto

import (
	"bytes"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
)

type PrivateKey struct {
	Key     []byte // The raw private key bytes
	KeyType string
}

type PublicKey struct {
	Key     []byte // The raw public key bytes
	KeyType string
}

// KeyStore is the server's callback seam into host-owned persistence
// The server holds a single long-lived private key per key type, shared across all clients
type KeyStore struct {
	GetPrivateKey         func(keyType string) *PrivateKey                     // Long-lived private key of the given type, nil if the server has none
	GetClientPublicKey    func(clientID string) *PublicKey                     // Current public key and its type, nil if unknown
	CommitClientPublicKey func(clientID string, newPublicKey *PublicKey) error // Persist after validated renewKeyAck
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
	session         *SessionAES256GCM
	privateKey      *PrivateKey
	clientPublicKey *PublicKey
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
// Only one handler per type, calling OnRequest twice for the same type replaces the prior handler
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
// Reserved types are handled internally, and app requests are dispatched to the handler
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
	if env.Version != protocolVersion {
		return write(s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errUnsupportedVersion))
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

	aad := computeAAD(env.Type, env.OriginID, env.TargetID, env.RequestID)
	plaintext, err := session.Decrypt(env.Payload, aad)
	if err != nil {
		return write(s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errDecryptionFailed))
	}

	// Reject replays (already seen requestId)
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
func (s *Server) sendResponse(env envelope, payload any, session *SessionAES256GCM, write WriteFn) error {
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
// RequestID on the wire is empty and clients use that to distinguish pushes from replies
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
func (s *Server) sessionFor(clientID string) (*SessionAES256GCM, string) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	clientPublicKey := s.keyStore.GetClientPublicKey(clientID)
	if clientPublicKey == nil {
		return nil, errNoClientKey
	}
	// Get server private key of the right type
	privateKey := s.keyStore.GetPrivateKey(clientPublicKey.KeyType)
	if privateKey == nil {
		return nil, errInvalidKey
	}

	// Reuse the cached session only if the key pair (bytes and type) hasn't changed
	if cached, ok := s.sessions[clientID]; ok &&
		cached.privateKey.KeyType == privateKey.KeyType && bytes.Equal(cached.privateKey.Key, privateKey.Key) &&
		cached.clientPublicKey.KeyType == clientPublicKey.KeyType && bytes.Equal(cached.clientPublicKey.Key, clientPublicKey.Key) {
		return cached.session, ""
	}

	// Derive session based on key type
	session, errCode := deriveSession(privateKey.KeyType, privateKey.Key, clientPublicKey.Key)
	if errCode != "" {
		return nil, errCode
	}
	s.sessions[clientID] = &cachedSession{
		session:         session,
		privateKey:      privateKey,
		clientPublicKey: clientPublicKey,
	}
	return session, ""
}

// buildEncryptedResponse produces a response envelope carrying encrypted payload bytes
// Pass nil payload for an empty-body success response
func (s *Server) buildEncryptedResponse(clientID, msgType string, payload []byte, requestID string, session *SessionAES256GCM) ([]byte, error) {
	aad := computeAAD(msgType, s.selfID, clientID, requestID)
	ciphertext, err := session.Encrypt(payload, aad)
	if err != nil {
		return nil, err
	}
	return marshalEnvelope(envelope{
		Version:   protocolVersion,
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
		Version:   protocolVersion,
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
