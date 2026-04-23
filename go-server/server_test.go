package rootproto

import (
	"strconv"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func fakeReplayStore() ReplayStore {
	var buf []byte
	return ReplayStore{
		Load:   func() ([]byte, error) { return buf, nil },
		Append: func(entry []byte) error { buf = append(buf, entry...); return nil },
		Save:   func(snapshot []byte) error { buf = snapshot; return nil },
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	server, err := NewServer("server", KeyStore{
		GetPrivateKey:         func() ([]byte, error) { return nil, nil },
		GetClientPublicKey:    func(string) ([]byte, bool) { return nil, false },
		CommitClientPublicKey: func(string, []byte) error { return nil },
	}, fakeReplayStore())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server
}

// Close is idempotent and guards post-close public calls
func TestCloseIsIdempotentAndGuardsFurtherUse(t *testing.T) {
	server := newTestServer(t)

	server.Close()
	server.Close() // should not panic

	noopWrite := func([]byte) error { return nil }
	if err := server.Push("client", "whatever", nil, noopWrite); err == nil {
		t.Error("Push after Close should return an error")
	}
	if err := server.Receive([]byte{0x00}, noopWrite); err == nil {
		t.Error("Receive after Close should return an error")
	}
	if err := server.OnRequest("ping", func(string, []byte, RespondFn) any { return nil }); err == nil {
		t.Error("OnRequest after Close should return an error")
	}
	if err := server.OffRequest("ping"); err == nil {
		t.Error("OffRequest after Close should return an error")
	}
}

func TestPushRejectsReservedTypes(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	noopWrite := func([]byte) error { return nil }

	for _, reserved := range []string{"renewKey", "renewKeyAck"} {
		err := server.Push("client", reserved, nil, noopWrite)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("Push(%q) should return a reserved-type error, got %v", reserved, err)
		}
	}
}

func TestOnRequestReplacesPriorHandler(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	var calls []string
	server.OnRequest("ping", func(string, []byte, RespondFn) any { calls = append(calls, "first"); return nil })
	server.OnRequest("ping", func(string, []byte, RespondFn) any { calls = append(calls, "second"); return nil })

	handler, ok := server.requestHandlers["ping"]
	if !ok {
		t.Fatal("expected a handler registered for ping")
	}
	handler("client", nil, nil)
	if strings.Join(calls, ",") != "second" {
		t.Errorf("expected only the second handler to fire, got %v", calls)
	}
	if len(server.requestHandlers) != 1 {
		t.Errorf("expected exactly one registered handler, got %d", len(server.requestHandlers))
	}
}

// Re-pairing can swap the stored client public key without going through renewKey; the next
// sessionFor call must re-derive rather than return the stale cached session
func TestSessionFromKeyChangesWhenStoredKeyChanges(t *testing.T) {
	serverKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (server): %v", err)
	}
	firstClient, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (first client): %v", err)
	}
	secondClient, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (second client): %v", err)
	}

	// Mutable store simulating a re-pair flow that swaps the client's public key
	currentClientPub := firstClient.PublicKey
	server, err := NewServer("server", KeyStore{
		GetPrivateKey:         func() ([]byte, error) { return serverKeypair.PrivateKey, nil },
		GetClientPublicKey:    func(string) ([]byte, bool) { return currentClientPub, true },
		CommitClientPublicKey: func(string, []byte) error { return nil },
	}, fakeReplayStore())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer server.Close()

	firstSession, errorCode := server.sessionFor("client-a")
	if errorCode != "" {
		t.Fatalf("first sessionFor failed: %s", errorCode)
	}

	// Re-pair: swap the client's public key out-from-under the server
	currentClientPub = secondClient.PublicKey

	secondSession, errorCode := server.sessionFor("client-a")
	if errorCode != "" {
		t.Fatalf("second sessionFor failed: %s", errorCode)
	}
	if firstSession == secondSession {
		t.Error("sessionFor should have re-derived after the stored client key changed")
	}

	// Verify the second session actually pairs with the new keys: a message encrypted under
	// the new shared secret should decrypt successfully
	expectedSecret, err := deriveSharedSecret(serverKeypair.PrivateKey, secondClient.PublicKey)
	if err != nil {
		t.Fatalf("deriveSharedSecret: %v", err)
	}
	expectedSession, err := SessionFromKey(expectedSecret)
	if err != nil {
		t.Fatalf("SessionFromKey: %v", err)
	}
	ciphertext, err := expectedSession.Encrypt([]byte("hello"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plaintext, err := secondSession.Decrypt(ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt with re-derived session failed: %v", err)
	}
	if string(plaintext) != "hello" {
		t.Errorf("unexpected plaintext: %q", plaintext)
	}
}

func TestReplayTrackerDetectsDuplicatesPerClient(t *testing.T) {
	tracker, err := newReplayTracker(fakeReplayStore())
	if err != nil {
		t.Fatalf("newReplayTracker: %v", err)
	}

	if seen, _ := tracker.checkAndRecord("client-a", "id-1"); seen {
		t.Error("first sighting of id-1 for client-a should not be a replay")
	}
	if seen, _ := tracker.checkAndRecord("client-a", "id-1"); !seen {
		t.Error("second sighting of id-1 for client-a should be detected as a replay")
	}
	if seen, _ := tracker.checkAndRecord("client-b", "id-1"); seen {
		t.Error("id-1 under client-b should not collide with client-a")
	}
}

func TestReplayTrackerDeleteClient(t *testing.T) {
	tracker, err := newReplayTracker(fakeReplayStore())
	if err != nil {
		t.Fatalf("newReplayTracker: %v", err)
	}

	tracker.checkAndRecord("client-a", "id-1")
	tracker.checkAndRecord("client-b", "id-1")

	if err := tracker.deleteClient("client-a"); err != nil {
		t.Fatalf("deleteClient: %v", err)
	}
	if seen, _ := tracker.checkAndRecord("client-a", "id-1"); seen {
		t.Error("id-1 for client-a should be accepted after delete")
	}
	if seen, _ := tracker.checkAndRecord("client-b", "id-1"); !seen {
		t.Error("client-b's id-1 should still be recorded")
	}
}

// Key rotation clears the client's replay history as part of handleRenewKeyAck
func TestRenewKeyAckClearsReplayHistory(t *testing.T) {
	// Real P-256 keys so the renewKeyAck ECDH + AEAD path can run
	serverKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	committed := make(map[string][]byte)
	server, err := NewServer("server", KeyStore{
		GetPrivateKey:         func() ([]byte, error) { return serverKeypair.PrivateKey, nil },
		GetClientPublicKey:    func(id string) ([]byte, bool) { pub, ok := committed[id]; return pub, ok },
		CommitClientPublicKey: func(id string, pub []byte) error { committed[id] = pub; return nil },
	}, fakeReplayStore())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer server.Close()

	clientID := "client-a"

	// Seed a requestID so we can verify it gets cleared
	server.replay.checkAndRecord(clientID, "seeded-id")

	// Buffer a pending new session as if handleRenewKey had run
	newClientKeypair, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	newSession, err := DeriveSession(serverKeypair.PrivateKey, newClientKeypair.PublicKey)
	if err != nil {
		t.Fatalf("DeriveSession: %v", err)
	}
	server.keys.bufferPending(clientID, newClientKeypair.PublicKey, newSession)

	// Build a valid renewKeyAck envelope encrypted under the new session
	ackPayload, err := cbor.Marshal(map[string]any{"ack": true})
	if err != nil {
		t.Fatalf("marshal ack: %v", err)
	}
	aad := computeAAD("renewKeyAck", clientID, server.selfID)
	ciphertext, err := newSession.Encrypt(ackPayload, aad)
	if err != nil {
		t.Fatalf("encrypt ack: %v", err)
	}
	ackEnv := envelope{
		Type:      "renewKeyAck",
		OriginID:  clientID,
		TargetID:  server.selfID,
		RequestID: "renew-1",
		Payload:   ciphertext,
	}

	server.handleRenewKeyAck(ackEnv)

	// After rotation, the seeded requestID should no longer be tracked
	if seen, _ := server.replay.checkAndRecord(clientID, "seeded-id"); seen {
		t.Error("seeded-id should be fresh after rotation (replay history not cleared)")
	}
}

// A partially-written trailing record (simulating a mid-write crash) must not break Load
// Valid records before the truncation are preserved regardless of how much of the tail was lost
func TestReplayTrackerRecoversFromTruncatedTail(t *testing.T) {
	for _, truncateBy := range []int{1, 2, 3, 5, 10, 20} {
		t.Run("truncate="+strconv.Itoa(truncateBy), func(t *testing.T) {
			var buf []byte
			store := ReplayStore{
				Load:   func() ([]byte, error) { return buf, nil },
				Append: func(entry []byte) error { buf = append(buf, entry...); return nil },
				Save:   func(snapshot []byte) error { buf = snapshot; return nil },
			}
			tracker, err := newReplayTracker(store)
			if err != nil {
				t.Fatalf("newReplayTracker: %v", err)
			}
			tracker.checkAndRecord("client-a", "id-1")
			tracker.checkAndRecord("client-a", "id-2")

			buf = buf[:len(buf)-truncateBy]

			reloaded, err := newReplayTracker(store)
			if err != nil {
				t.Fatalf("newReplayTracker after truncation: %v", err)
			}
			if seen, _ := reloaded.checkAndRecord("client-a", "id-1"); !seen {
				t.Error("id-1 (fully persisted) should survive truncation")
			}
			if seen, _ := reloaded.checkAndRecord("client-a", "id-2"); seen {
				t.Error("id-2 (partially written) should be treated as unseen")
			}
		})
	}
}

// ClearClient drops both session and replay state; a fresh Server afterwards sees no history
func TestClearClientDropsSessionAndReplayHistory(t *testing.T) {
	store := fakeReplayStore()
	keyStore := KeyStore{
		GetPrivateKey:         func() ([]byte, error) { return nil, nil },
		GetClientPublicKey:    func(string) ([]byte, bool) { return nil, false },
		CommitClientPublicKey: func(string, []byte) error { return nil },
	}

	first, err := NewServer("server", keyStore, store)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Seed both the session cache and the replay history for client-a
	first.sessions["client-a"] = &cachedSession{}
	first.replay.checkAndRecord("client-a", "id-1")
	first.replay.checkAndRecord("client-b", "id-2")

	if err := first.ClearClient("client-a"); err != nil {
		t.Fatalf("ClearClient: %v", err)
	}
	if _, ok := first.sessions["client-a"]; ok {
		t.Error("client-a's cached session should be dropped")
	}
	first.Close()

	second, err := NewServer("server", keyStore, store)
	if err != nil {
		t.Fatalf("NewServer (reload): %v", err)
	}
	defer second.Close()
	if seen, _ := second.replay.checkAndRecord("client-a", "id-1"); seen {
		t.Error("client-a's id-1 should be fresh after delete+reload")
	}
	if seen, _ := second.replay.checkAndRecord("client-b", "id-2"); !seen {
		t.Error("client-b's id-2 should survive delete of client-a")
	}
}
