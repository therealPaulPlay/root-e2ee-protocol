// test_server is a Unix-domain-socket helper used by the JS cross-language e2e tests
// Framing: 4-byte big-endian length prefix + raw envelope bytes
//
// CLI flags:
//
//	-socket <path>            UDS path to listen on
//	-self-id <string>         server's own ID
//	-private-key <hex>        server's 32-byte private key
//	-client-id <string>       the single paired client's ID
//	-client-pub <hex>         the client's 65-byte public key
//	-drop-ack                 if set, the server suppresses renewKeyAckResult to simulate a lost ACK
//
// Registered handlers (so the JS test can exercise them):
//
//	echo                  returns the incoming payload unchanged
//	add                   expects {a, b} and returns {sum}
//	trigger-push          sends a server Push of type "tick" carrying {n: 42}, then replies {ok: true}
//	push-under-stashed    builds and writes a push envelope encrypted with the stashed pre-renewal
//	                      session, bypassing the server's live session cache. The stash is taken
//	                      automatically inside CommitClientPublicKey just before a key rotation,
//	                      so this handler exercises the case where an in-flight push from before
//	                      a renewal arrives after the client has already committed a new key
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/fxamacker/cbor/v2"
	rp "github.com/therealPaulPlay/root-e2ee-protocol/go-server"
)

func main() {
	var (
		socketPath  = flag.String("socket", "", "Unix socket path")
		selfID      = flag.String("self-id", "", "server self ID")
		privKeyHex  = flag.String("private-key", "", "server private key, hex-encoded (32 bytes)")
		clientID    = flag.String("client-id", "", "paired client ID")
		clientPub   = flag.String("client-pub", "", "client public key, hex-encoded (65 bytes)")
		dropACKFlag = flag.Bool("drop-ack", false, "if set, the server suppresses the renewKeyAck reply to simulate a lost ACK")
	)
	flag.Parse()

	if *socketPath == "" || *selfID == "" || *privKeyHex == "" || *clientID == "" || *clientPub == "" {
		log.Fatal("missing required flags")
	}

	privKey, err := hex.DecodeString(*privKeyHex)
	if err != nil {
		log.Fatalf("decode private key: %v", err)
	}
	clientPubKey, err := hex.DecodeString(*clientPub)
	if err != nil {
		log.Fatalf("decode client public key: %v", err)
	}

	// Client public key is mutable so the test can rotate it via renewKeyAck
	// stashedClientPub holds a snapshot taken before the most recent renewal (test-only)
	var keyMu sync.Mutex
	currentClientPub := clientPubKey
	var stashedClientPub []byte

	keyStore := rp.KeyStore{
		GetPrivateKey: func() ([]byte, error) { return privKey, nil },
		GetClientPublicKey: func(id string) ([]byte, bool) {
			if id != *clientID {
				return nil, false
			}
			keyMu.Lock()
			defer keyMu.Unlock()
			return append([]byte(nil), currentClientPub...), true
		},
		CommitClientPublicKey: func(id string, newPub []byte) error {
			keyMu.Lock()
			defer keyMu.Unlock()
			// Stash the outgoing public key before replacing it (test-only)
			stashedClientPub = append([]byte(nil), currentClientPub...)
			currentClientPub = append([]byte(nil), newPub...)
			return nil
		},
	}

	// Frames are processed sequentially, so the ReplayStore doesn't need its own lock
	var replayBuf []byte
	replayStore := rp.ReplayStore{
		Load:   func() ([]byte, error) { return replayBuf, nil },
		Append: func(entry []byte) error { replayBuf = append(replayBuf, entry...); return nil },
		Save:   func(snapshot []byte) error { replayBuf = snapshot; return nil },
	}

	server, err := rp.NewServer(*selfID, keyStore, replayStore)
	if err != nil {
		log.Fatalf("new server: %v", err)
	}
	defer server.Close()

	// Clean up any leftover socket
	_ = os.Remove(*socketPath)
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	// Signal readiness so the JS test knows when to connect
	fmt.Println("READY")

	// Shutdown path on signal so the JS test can kill cleanly
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		listener.Close()
	}()

	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	writeFn := func(bytes []byte) error {
		return writeFrame(conn, bytes)
	}

	// Register handlers (writeFn is closed over for trigger-push)
	server.OnRequest("echo", func(_ string, payload []byte) any {
		var body any
		if err := cbor.Unmarshal(payload, &body); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return body
	})
	server.OnRequest("add", func(_ string, payload []byte) any {
		var req struct {
			A int64 `cbor:"a"`
			B int64 `cbor:"b"`
		}
		if err := cbor.Unmarshal(payload, &req); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"sum": req.A + req.B}
	})
	server.OnRequest("trigger-push", func(clientID string, _ []byte) any {
		// Send an unsolicited push to the client, then reply normally
		if err := server.Push(clientID, "tick", map[string]any{"n": 42}, writeFn); err != nil {
			log.Printf("push failed: %v", err)
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true}
	})
	server.OnRequest("push-under-stashed", func(clientID string, _ []byte) any {
		keyMu.Lock()
		pub := append([]byte(nil), stashedClientPub...)
		keyMu.Unlock()
		if len(pub) == 0 {
			return map[string]any{"ok": false, "error": "no stashed session"}
		}
		if err := pushWithKey(conn, *selfID, clientID, "stale-tick", map[string]any{"stale": true}, privKey, pub); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true}
	})

	for {
		frame, err := readFrame(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("read: %v", err)
			}
			return
		}
		// Drop inbound renewKeyAck frames when the flag is set, so the server never commits
		// the new client public key even though the client has already committed locally
		if *dropACKFlag {
			var shallow map[string]any
			if err := cbor.Unmarshal(frame, &shallow); err == nil {
				if t, _ := shallow["type"].(string); t == "renewKeyAck" {
					continue
				}
			}
		}
		if err := server.Receive(frame, writeFn); err != nil {
			log.Printf("receive: %v", err)
		}
	}
}

func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFrame(w io.Writer, payload []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// pushWithKey hand-builds and writes a push envelope using the supplied key pair
// Bypasses the server's session cache on purpose: the test uses this to deliver a push
// encrypted under a session that has already been retired by a subsequent key renewal
func pushWithKey(w io.Writer, selfID, clientID, msgType string, payload any, privKey, clientPub []byte) error {
	session, err := rp.DeriveSession(privKey, clientPub)
	if err != nil {
		return err
	}
	payloadCBOR, err := cbor.Marshal(payload)
	if err != nil {
		return err
	}
	aadHash := sha256.Sum256([]byte(msgType + "|" + selfID + "|" + clientID))
	aad := aadHash[:]
	ciphertext, err := session.Encrypt(payloadCBOR, aad)
	if err != nil {
		return err
	}
	envBytes, err := cbor.Marshal(map[string]any{
		"type":      msgType,
		"originId":  selfID,
		"targetId":  clientID,
		"requestId": "",
		"payload":   ciphertext,
	})
	if err != nil {
		return err
	}
	return writeFrame(w, envBytes)
}
