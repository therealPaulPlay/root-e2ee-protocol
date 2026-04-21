package rootproto

import (
	"strings"
	"testing"
)

func TestPushRejectsReservedTypes(t *testing.T) {
	server := NewServer("server", KeyStore{
		GetPrivateKey:         func() ([]byte, error) { return nil, nil },
		GetClientPublicKey:    func(string) ([]byte, bool) { return nil, false },
		CommitClientPublicKey: func(string, []byte) error { return nil },
	})
	defer server.Close()

	noopWrite := func(string, []byte) error { return nil }

	for _, reserved := range []string{"renewKey", "renewKeyAck"} {
		err := server.Push("client", reserved, nil, noopWrite)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("Push(%q) should return a reserved-type error, got %v", reserved, err)
		}
	}
}
