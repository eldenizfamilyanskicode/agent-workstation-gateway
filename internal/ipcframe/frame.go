package ipcframe

import (
	"encoding/binary"
	"fmt"
	"io"

	v1 "github.com/eldenizfamilyanskicode/agent-workstation-gateway/protocol/v1"
)

const (
	HeaderBytes   = 4
	MaxFrameBytes = v1.MaxExecutionReportBytes
)

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("broker IPC frame failed: %s", failure.Rule)
}

func Read(reader io.Reader, maximum int) ([]byte, error) {
	if reader == nil || maximum <= 0 || maximum > MaxFrameBytes {
		return nil, frameError("invalid-read-policy")
	}
	header := make([]byte, HeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, frameError("header-truncated")
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || uint64(size) > uint64(maximum) {
		return nil, frameError("payload-size-denied")
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, frameError("payload-truncated")
	}
	return payload, nil
}

func Write(writer io.Writer, payload []byte, maximum int) error {
	if writer == nil || maximum <= 0 || maximum > MaxFrameBytes {
		return frameError("invalid-write-policy")
	}
	if len(payload) == 0 || len(payload) > maximum {
		return frameError("payload-size-denied")
	}
	frame := make([]byte, HeaderBytes+len(payload))
	binary.BigEndian.PutUint32(frame[:HeaderBytes], uint32(len(payload)))
	copy(frame[HeaderBytes:], payload)
	written := 0
	for written < len(frame) {
		count, err := writer.Write(frame[written:])
		if count < 0 || count > len(frame)-written {
			return frameError("write-count-invalid")
		}
		written += count
		if err != nil {
			return frameError("write-failed")
		}
		if count == 0 {
			return frameError("write-short")
		}
	}
	return nil
}

func frameError(rule string) error {
	return &Error{Rule: rule}
}
