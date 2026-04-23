package rootproto

import (
	"encoding/binary"
	"hash/crc32"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// ReplayStore is the host's callback seam for persisting seen requestIDs
// Append is called after every accepted message; Save replaces the persisted
// state on client deletion; Load returns the concatenation of every record
// the host has persisted
type ReplayStore struct {
	Load   func() ([]byte, error)
	Append func(entry []byte) error
	Save   func(snapshot []byte) error
}

const (
	kindSnapshot byte = 1
	kindEntry    byte = 2
)

type replayTracker struct {
	store ReplayStore
	mu    sync.Mutex
	sets  map[string]map[string]struct{}
}

func newReplayTracker(store ReplayStore) (*replayTracker, error) {
	bytes, err := store.Load()
	if err != nil {
		return nil, err
	}
	sets, err := parseReplayLog(bytes)
	if err != nil {
		return nil, err
	}
	return &replayTracker{store: store, sets: sets}, nil
}

func (t *replayTracker) checkAndRecord(clientID, requestID string) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	set, ok := t.sets[clientID]
	if !ok {
		set = make(map[string]struct{})
		t.sets[clientID] = set
	}
	if _, seen := set[requestID]; seen {
		return true, nil // Replay found
	}
	set[requestID] = struct{}{}

	record, err := encodeEntryRecord(clientID, requestID)
	if err != nil {
		delete(set, requestID)
		return false, err // Rollback on error
	}
	if err := t.store.Append(record); err != nil {
		delete(set, requestID)
		return false, err // Rollback on error
	}
	return false, nil
}

func (t *replayTracker) deleteClient(clientID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sets, clientID)
	// Create snapshot of the state & save
	snapshot, err := encodeSnapshotRecord(t.sets)
	if err != nil {
		return err
	}
	return t.store.Save(snapshot)
}

// Subsequent, single entry
func encodeEntryRecord(clientID, requestID string) ([]byte, error) {
	payload, err := cbor.Marshal([]string{clientID, requestID})
	if err != nil {
		return nil, err
	}
	return frameRecord(kindEntry, payload), nil
}

// Full snapshot of all entries
func encodeSnapshotRecord(sets map[string]map[string]struct{}) ([]byte, error) {
	flat := make(map[string][]string, len(sets))
	for clientID, set := range sets {
		ids := make([]string, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		flat[clientID] = ids
	}
	payload, err := cbor.Marshal(flat)
	if err != nil {
		return nil, err
	}
	return frameRecord(kindSnapshot, payload), nil
}

// Record framing: [kind 1B][varint length][payload][CRC32 4B over kind+length+payload]
// The trailing CRC distinguishes a complete record from a crash-truncated one
func frameRecord(kind byte, payload []byte) []byte {
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(payload)))

	body := make([]byte, 0, 1+n+len(payload))
	body = append(body, kind)
	body = append(body, lenBuf[:n]...)
	body = append(body, payload...)

	sum := crc32.ChecksumIEEE(body)
	var crcBuf [4]byte
	binary.BigEndian.PutUint32(crcBuf[:], sum)

	return append(body, crcBuf[:]...)
}

// parseReplayLog walks a concatenation of framed records and returns the
// reconstructed per-client sets
// Per-record CRC means a truncated or corrupted trailing record stops parsing
// cleanly; the stale tail is compacted out on the next Save
func parseReplayLog(data []byte) (map[string]map[string]struct{}, error) {
	sets := make(map[string]map[string]struct{})
	for len(data) > 0 {
		kind := data[0]
		rest := data[1:]

		length, n := binary.Uvarint(rest)
		if n <= 0 {
			return sets, nil
		}
		rest = rest[n:]
		if uint64(len(rest)) < length+4 {
			return sets, nil
		}
		payload := rest[:length]
		gotCRC := binary.BigEndian.Uint32(rest[length : length+4])

		bodyLen := 1 + n + int(length)
		wantCRC := crc32.ChecksumIEEE(data[:bodyLen])
		if gotCRC != wantCRC {
			return sets, nil
		}
		data = rest[length+4:]

		switch kind {
		case kindSnapshot:
			var flat map[string][]string
			if err := cbor.Unmarshal(payload, &flat); err != nil {
				return sets, nil
			}
			sets = make(map[string]map[string]struct{}, len(flat))
			for clientID, ids := range flat {
				set := make(map[string]struct{}, len(ids))
				for _, id := range ids {
					set[id] = struct{}{}
				}
				sets[clientID] = set
			}
		case kindEntry:
			var pair []string
			if err := cbor.Unmarshal(payload, &pair); err != nil || len(pair) != 2 {
				return sets, nil
			}
			set, ok := sets[pair[0]]
			if !ok {
				set = make(map[string]struct{})
				sets[pair[0]] = set
			}
			set[pair[1]] = struct{}{}
		default:
			return sets, nil
		}
	}
	return sets, nil
}
