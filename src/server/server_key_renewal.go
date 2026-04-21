package rootproto

import "github.com/fxamacker/cbor/v2"

// handleRenewKey processes a client's renewKey request
// Decrypts with the OLD session, buffers the proposed new session as "pending",
// and replies with an empty encrypted success under the OLD session
func (s *Server) handleRenewKey(env envelope) []byte {
	clientPub, ok := s.keyStore.GetClientPublicKey(env.OriginID)
	if !ok {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrNoClientKey)
	}
	priv, err := s.keyStore.GetPrivateKey()
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrInvalidKey)
	}

	oldSecret, err := DeriveSharedSecret(priv, clientPub)
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrInvalidKey)
	}
	oldSession, err := SessionFromKey(oldSecret)
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrInternalError)
	}

	aad := computeAAD(env.Type, env.OriginID, env.TargetID)
	plaintext, err := oldSession.Decrypt(env.Payload, aad)
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrDecryptionFailed)
	}

	var req struct {
		NewPublicKey []byte `cbor:"newPublicKey"`
	}
	if err := cbor.Unmarshal(plaintext, &req); err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrInvalidPayload)
	}

	newSecret, err := DeriveSharedSecret(priv, req.NewPublicKey)
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrInvalidKey)
	}
	newSession, err := SessionFromKey(newSecret)
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrInternalError)
	}

	s.keys.bufferPending(env.OriginID, req.NewPublicKey, newSession)

	out, err := s.buildEncryptedReply(env.OriginID, env.Type+resultSuffix, nil, env.RequestID, oldSession)
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrInternalError)
	}
	return out
}

// handleRenewKeyAck processes a client's renewKeyAck
// Decrypts with the pending NEW session, commits the client's new public key,
// invalidates the session cache, and replies with empty success under the new session
func (s *Server) handleRenewKeyAck(env envelope) []byte {
	pending, ok := s.keys.takePending(env.OriginID)
	if !ok {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrInternalError)
	}

	aad := computeAAD(env.Type, env.OriginID, env.TargetID)
	plaintext, err := pending.session.Decrypt(env.Payload, aad)
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrDecryptionFailed)
	}

	var req struct {
		Ack bool `cbor:"ack"`
	}
	if err := cbor.Unmarshal(plaintext, &req); err != nil || !req.Ack {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrInvalidPayload)
	}

	if err := s.keyStore.CommitClientPublicKey(env.OriginID, pending.clientPublicKey); err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrInternalError)
	}

	s.invalidateSession(env.OriginID)

	out, err := s.buildEncryptedReply(env.OriginID, env.Type+resultSuffix, nil, env.RequestID, pending.session)
	if err != nil {
		return s.buildProtocolError(env.OriginID, env.RequestID, env.Type, ErrInternalError)
	}
	return out
}
