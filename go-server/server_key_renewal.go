package rootproto

import "github.com/fxamacker/cbor/v2"

// handleRenewKey processes a client's renewKey request
// Decrypts with the OLD session, buffers the proposed new session as "pending",
// and replies with an empty encrypted success under the OLD session
func (s *Server) handleRenewKey(env envelope) []byte {
	clientPublicKey := s.keyStore.GetClientPublicKey(env.OriginID)
	if clientPublicKey == nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errNoClientKey)
	}
	// The current session uses the server's key matching the client's current key type
	oldPrivateKey := s.keyStore.GetPrivateKey(clientPublicKey.KeyType)
	if oldPrivateKey == nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errInvalidKey)
	}
	oldSession, errCode := deriveSession(oldPrivateKey.KeyType, oldPrivateKey.Key, clientPublicKey.Key)
	if errCode != "" {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errCode)
	}

	aad := computeAAD(env.Type, env.OriginID, env.TargetID, env.RequestID)
	plaintext, err := oldSession.Decrypt(env.Payload, aad)
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errDecryptionFailed)
	}

	var req struct {
		NewPublicKey []byte `cbor:"newPublicKey"`
	}
	if err := cbor.Unmarshal(plaintext, &req); err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errInvalidPayload)
	}

	// Renewal keeps the established type, deriving with it rejects a new key of any other type
	newSession, errCode := deriveSession(oldPrivateKey.KeyType, oldPrivateKey.Key, req.NewPublicKey)
	if errCode != "" {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errCode)
	}

	s.keys.bufferPending(env.OriginID, &PublicKey{Key: req.NewPublicKey, KeyType: clientPublicKey.KeyType}, newSession)

	out, err := s.buildEncryptedResponse(env.OriginID, env.Type, nil, env.RequestID, oldSession)
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errInternalError)
	}
	return out
}

// handleRenewKeyAck processes a client's renewKeyAck
// Decrypts with the pending NEW session, commits the client's new public key,
// invalidates the session cache, and replies with empty success under the new session
func (s *Server) handleRenewKeyAck(env envelope) []byte {
	pending, ok := s.keys.takePending(env.OriginID)
	if !ok {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errInternalError)
	}

	aad := computeAAD(env.Type, env.OriginID, env.TargetID, env.RequestID)
	plaintext, err := pending.session.Decrypt(env.Payload, aad)
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errDecryptionFailed)
	}

	var req struct {
		Ack bool `cbor:"ack"`
	}
	if err := cbor.Unmarshal(plaintext, &req); err != nil || !req.Ack {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errInvalidPayload)
	}

	if err := s.keyStore.CommitClientPublicKey(env.OriginID, pending.clientPublicKey); err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errInternalError)
	}

	if err := s.replay.deleteClient(env.OriginID); err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errInternalError)
	}

	out, err := s.buildEncryptedResponse(env.OriginID, env.Type, nil, env.RequestID, pending.session)
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, errInternalError)
	}
	return out
}
