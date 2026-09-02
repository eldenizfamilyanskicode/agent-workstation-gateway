package outputcapture

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

func TestCaptureHashesAllBytesAndRetainsBoundedPrefix(t *testing.T) {
	capture, err := New(v1.MinOutputBytes)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(strings.Repeat("a", v1.MinOutputBytes) + strings.Repeat("b", 37))
	written, err := capture.Write(content)
	if err != nil || written != len(content) {
		t.Fatalf("write failed: %d / %v", written, err)
	}
	snapshot, err := capture.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if snapshot.Metadata.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("capture digest does not cover the complete observed stream")
	}
	if snapshot.Metadata.TotalBytes != int64(len(content)) || snapshot.Metadata.RetainedBytes != v1.MinOutputBytes || !snapshot.Metadata.Truncated {
		t.Fatalf("unexpected capture metadata: %#v", snapshot.Metadata)
	}
	if string(snapshot.Retained) != strings.Repeat("a", v1.MinOutputBytes) {
		t.Fatal("capture did not retain the observed prefix")
	}
}

func TestCaptureUntruncatedMetadataAndSnapshotCopy(t *testing.T) {
	capture, err := New(v1.MinOutputBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capture.Write([]byte("done\n")); err != nil {
		t.Fatal(err)
	}
	first, err := capture.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	first.Retained[0] = 'X'
	second, err := capture.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if second.Metadata.Truncated || second.Metadata.TotalBytes != 5 || second.Metadata.RetainedBytes != 5 || string(second.Retained) != "done\n" {
		t.Fatalf("unexpected untruncated snapshot: %#v", second)
	}
}

func TestCaptureRejectsLimitsOutsideProtocolBounds(t *testing.T) {
	for _, limit := range []int{v1.MinOutputBytes - 1, v1.MaxOutputBytes + 1} {
		_, err := New(limit)
		if !errors.Is(err, ErrInvalidLimit) {
			t.Fatalf("limit %d did not return ErrInvalidLimit: %v", limit, err)
		}
	}
}

func TestCaptureConcurrentWritesRemainBounded(t *testing.T) {
	capture, err := New(v1.MinOutputBytes)
	if err != nil {
		t.Fatal(err)
	}
	const writerCount = 32
	const bytesPerWriter = 257
	var writers sync.WaitGroup
	for index := 0; index < writerCount; index++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			if _, err := capture.Write([]byte(strings.Repeat("x", bytesPerWriter))); err != nil {
				t.Errorf("concurrent write failed: %v", err)
			}
		}()
	}
	writers.Wait()
	snapshot, err := capture.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Metadata.TotalBytes != writerCount*bytesPerWriter || snapshot.Metadata.RetainedBytes != v1.MinOutputBytes || !snapshot.Metadata.Truncated {
		t.Fatalf("unexpected concurrent capture metadata: %#v", snapshot.Metadata)
	}
}
