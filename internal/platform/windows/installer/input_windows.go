//go:build windows

package installer

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/protectedstate"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/sourceversion"
)

const (
	peOffsetLocation      = 0x3c
	peFileHeaderBytes     = 24
	peMachineAMD64        = 0x8664
	peOptionalMagicPE32P  = 0x20b
	peExecutableImageFlag = 0x0002
	peDLLFlag             = 0x2000
)

type Input struct {
	Specification    installplan.Spec
	GatewaySourceSHA string
	BrokerImage      []byte
}

type preparedInput struct {
	specification    installplan.Spec
	gatewaySourceSHA string
	brokerImage      []byte
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows installation transaction failed: %s", failure.Rule)
}

func prepareInput(input Input) (preparedInput, error) {
	if _, err := installplan.Build(input.Specification); err != nil {
		return preparedInput{}, installerError("install-specification-invalid")
	}
	if !sourceversion.IsCanonicalGitSHA(input.GatewaySourceSHA) {
		return preparedInput{}, installerError("gateway-source-sha-invalid")
	}
	if !validBrokerImage(input.BrokerImage, input.GatewaySourceSHA) {
		return preparedInput{}, installerError("broker-image-invalid")
	}
	return preparedInput{
		specification:    cloneSpecification(input.Specification),
		gatewaySourceSHA: input.GatewaySourceSHA,
		brokerImage:      append([]byte(nil), input.BrokerImage...),
	}, nil
}

func validBrokerImage(image []byte, sourceSHA string) bool {
	if len(image) < peOffsetLocation+4 || len(image) > protectedstate.MaxProtectedExecutableBytes ||
		image[0] != 'M' || image[1] != 'Z' || !bytes.Contains(image, []byte(sourceSHA)) {
		return false
	}
	header := uint64(binary.LittleEndian.Uint32(image[peOffsetLocation : peOffsetLocation+4]))
	if header > uint64(len(image)-peFileHeaderBytes) {
		return false
	}
	offset := int(header)
	if !bytes.Equal(image[offset:offset+4], []byte{'P', 'E', 0, 0}) ||
		binary.LittleEndian.Uint16(image[offset+4:offset+6]) != peMachineAMD64 {
		return false
	}
	optionalBytes := int(binary.LittleEndian.Uint16(image[offset+20 : offset+22]))
	characteristics := binary.LittleEndian.Uint16(image[offset+22 : offset+24])
	optionalStart := offset + peFileHeaderBytes
	if optionalBytes < 2 || optionalStart > len(image)-optionalBytes ||
		binary.LittleEndian.Uint16(image[optionalStart:optionalStart+2]) != peOptionalMagicPE32P ||
		characteristics&peExecutableImageFlag == 0 || characteristics&peDLLFlag != 0 {
		return false
	}
	return true
}

func cloneSpecification(specification installplan.Spec) installplan.Spec {
	specification.ApprovedRoots = append([]string(nil), specification.ApprovedRoots...)
	specification.Shells = append([]installconfig.ShellBinding(nil), specification.Shells...)
	specification.PathEntries = append([]string(nil), specification.PathEntries...)
	specification.Capabilities = append([]installconfig.Capability(nil), specification.Capabilities...)
	return specification
}

func installerError(rule string) error { return &Error{Rule: rule} }
