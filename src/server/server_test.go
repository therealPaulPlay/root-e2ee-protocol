package rootproto

import (
	"fmt"
	"strings"
	"testing"
)

func newTestServer() *Server {
	return NewServer("server", KeyStore{
		GetPrivateKey:         func() ([]byte, error) { return nil, nil },
		GetClientPublicKey:    func(string) ([]byte, bool) { return nil, false },
		CommitClientPublicKey: func(string, []byte) error { return nil },
	})
}

func TestPushRejectsReservedTypes(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	noopWrite := func(string, []byte) error { return nil }

	for _, reserved := range []string{"renewKey", "renewKeyAck"} {
		err := server.Push("client", reserved, nil, noopWrite)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("Push(%q) should return a reserved-type error, got %v", reserved, err)
		}
	}
}

func TestOnRequestReplacesPriorHandler(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	var calls []string
	server.OnRequest("ping", func(string, []byte) any { calls = append(calls, "first"); return nil })
	server.OnRequest("ping", func(string, []byte) any { calls = append(calls, "second"); return nil })

	handler, ok := server.requestHandlers["ping"]
	if !ok {
		t.Fatal("expected a handler registered for ping")
	}
	handler("client", nil)
	if strings.Join(calls, ",") != "second" {
		t.Errorf("expected only the second handler to fire, got %v", calls)
	}
	if len(server.requestHandlers) != 1 {
		t.Errorf("expected exactly one registered handler, got %d", len(server.requestHandlers))
	}
}

func TestReplayCacheDetectsDuplicates(t *testing.T) {
	c := newReplayCache()

	if c.check("id-1") {
		t.Error("first sighting of id-1 should not be a replay")
	}
	if !c.check("id-1") {
		t.Error("second sighting of id-1 should be detected as a replay")
	}
	if c.check("id-2") {
		t.Error("distinct id-2 should not be a replay")
	}
}

func TestReplayCacheEvictsOldestAtCapacity(t *testing.T) {
	c := newReplayCache()

	// Fill to capacity with unique IDs
	for i := 0; i < replayCacheSize; i++ {
		if c.check(uniqueID(i)) {
			t.Fatalf("fresh id at position %d unexpectedly flagged", i)
		}
	}
	// The oldest insertion (id-0) is still in the cache right now
	if !c.check(uniqueID(0)) {
		t.Error("id-0 should still be in cache at exactly capacity")
	}

	// Insert one more fresh id. Since id-0's re-check was a pure lookup (no insert),
	// the ring buffer head still points at the id-0 slot - The new insert evicts id-0
	c.check("overflow-1")
	if c.check(uniqueID(0)) {
		t.Error("id-0 should have been evicted and accepted as fresh again")
	}
}

func uniqueID(i int) string {
	return fmt.Sprintf("id-%d", i)
}
