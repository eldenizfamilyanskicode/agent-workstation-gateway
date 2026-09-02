package ipcframe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte("synthetic broker payload")
	var encoded bytes.Buffer
	if err := Write(&encoded, payload, 1024); err != nil {
		t.Fatal(err)
	}
	decoded, err := Read(&encoded, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, payload) || encoded.Len() != 0 {
		t.Fatal("framed payload did not round-trip exactly")
	}
}

func TestReadRejectsSizeBeforePayloadAllocation(t *testing.T) {
	header := make([]byte, HeaderBytes)
	binary.BigEndian.PutUint32(header, 1025)
	_, err := Read(bytes.NewReader(header), 1024)
	assertFrameError(t, err, "payload-size-denied")
}

func TestFrameRejectsTruncationZeroAndShortWrite(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
		rule string
	}{
		{name: "short header", run: func() error { _, err := Read(bytes.NewReader([]byte{0, 1}), 1024); return err }, rule: "header-truncated"},
		{name: "zero", run: func() error { _, err := Read(bytes.NewReader(make([]byte, HeaderBytes)), 1024); return err }, rule: "payload-size-denied"},
		{name: "short payload", run: func() error {
			frame := make([]byte, HeaderBytes+2)
			binary.BigEndian.PutUint32(frame, 3)
			_, err := Read(bytes.NewReader(frame), 1024)
			return err
		}, rule: "payload-truncated"},
		{name: "empty write", run: func() error { return Write(io.Discard, nil, 1024) }, rule: "payload-size-denied"},
		{name: "short write", run: func() error { return Write(shortWriter{}, []byte("x"), 1024) }, rule: "write-short"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertFrameError(t, test.run(), test.rule)
		})
	}
}

func TestFrameRejectsUnboundedPolicy(t *testing.T) {
	_, err := Read(bytes.NewReader(nil), MaxFrameBytes+1)
	assertFrameError(t, err, "invalid-read-policy")
	assertFrameError(t, Write(io.Discard, []byte("x"), MaxFrameBytes+1), "invalid-write-policy")
}

func assertFrameError(t *testing.T, err error, rule string) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Rule != rule {
		t.Fatalf("expected %s, got %T / %v", rule, err, err)
	}
}
