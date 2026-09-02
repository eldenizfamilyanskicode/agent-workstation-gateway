package outputcapture

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"math"
	"sync"

	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

var ErrInvalidLimit = errors.New("output capture limit is outside protocol bounds")
var ErrByteCountOverflow = errors.New("output capture byte count overflow")

type Capture struct {
	mu       sync.Mutex
	limit    int
	digest   hash.Hash
	total    uint64
	retained []byte
}

type Snapshot struct {
	Metadata v1.OutputMetadata
	Retained []byte
}

func New(limit int) (*Capture, error) {
	if limit < v1.MinOutputBytes || limit > v1.MaxOutputBytes {
		return nil, ErrInvalidLimit
	}
	return &Capture{
		limit:    limit,
		digest:   sha256.New(),
		retained: make([]byte, 0, limit),
	}, nil
}

func (capture *Capture) Write(content []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if uint64(len(content)) > math.MaxUint64-capture.total {
		return 0, ErrByteCountOverflow
	}
	if _, err := capture.digest.Write(content); err != nil {
		return 0, err
	}
	capture.total += uint64(len(content))
	remaining := capture.limit - len(capture.retained)
	if remaining > len(content) {
		remaining = len(content)
	}
	if remaining > 0 {
		capture.retained = append(capture.retained, content[:remaining]...)
	}
	return len(content), nil
}

func (capture *Capture) Snapshot() (Snapshot, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.total > math.MaxInt64 {
		return Snapshot{}, ErrByteCountOverflow
	}
	digest := capture.digest.Sum(nil)
	retained := append([]byte(nil), capture.retained...)
	return Snapshot{
		Metadata: v1.OutputMetadata{
			SHA256:        hex.EncodeToString(digest),
			TotalBytes:    int64(capture.total),
			RetainedBytes: int64(len(retained)),
			Truncated:     uint64(len(retained)) < capture.total,
		},
		Retained: retained,
	}, nil
}
