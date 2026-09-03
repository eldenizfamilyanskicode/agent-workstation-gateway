//go:build windows

package installer

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installmetadata"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installplan"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/platform/windows/protectedstate"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerpackage"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/runnerregistration"
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
	Specification      installplan.Spec
	GatewaySourceSHA   string
	BrokerImage        []byte
	ControlImage       []byte
	RunnerImage        *runnerpackage.Image
	RunnerRegistration runnerregistration.Request
	Metadata           installmetadata.Metadata
}

type preparedInput struct {
	specification      installplan.Spec
	gatewaySourceSHA   string
	brokerImage        []byte
	controlImage       []byte
	runnerImage        *runnerpackage.Image
	runnerRegistration runnerregistration.Request
	metadata           []byte
}

type Error struct {
	Rule string
}

func ValidateReleaseImages(gatewaySourceSHA string, brokerImage []byte, controlImage []byte) error {
	if !sourceversion.IsCanonicalGitSHA(gatewaySourceSHA) {
		return installerError("gateway-source-sha-invalid")
	}
	if !validBrokerImage(brokerImage, gatewaySourceSHA) {
		return installerError("broker-image-invalid")
	}
	if !validBrokerImage(controlImage, gatewaySourceSHA) {
		return installerError("control-image-invalid")
	}
	return nil
}

func (failure *Error) Error() string {
	return fmt.Sprintf("Windows installation transaction failed: %s", failure.Rule)
}

func prepareInput(input Input) (preparedInput, error) {
	return prepareInputWithPolicy(input, true)
}

func prepareInputWithPolicy(input Input, requirePinnedRunner bool) (preparedInput, error) {
	if _, err := installplan.Build(input.Specification); err != nil {
		return preparedInput{}, installerError("install-specification-invalid")
	}
	if err := ValidateReleaseImages(input.GatewaySourceSHA, input.BrokerImage, input.ControlImage); err != nil {
		return preparedInput{}, err
	}
	if input.RunnerImage == nil || input.RunnerImage.Version() == "" ||
		(requirePinnedRunner && !input.RunnerImage.PinnedWindowsX64()) {
		return preparedInput{}, installerError("runner-image-invalid")
	}
	registration := cloneRegistration(input.RunnerRegistration)
	if err := runnerregistration.ValidateRequest(input.Specification.InstallationRoot, registration); err != nil {
		zeroBytes(registration.RegistrationToken)
		zeroBytes(registration.RemovalToken)
		return preparedInput{}, installerError("runner-registration-invalid")
	}
	if err := installmetadata.Validate(input.Metadata); err != nil ||
		input.Metadata.InstallationRoot != input.Specification.InstallationRoot ||
		input.Metadata.GatewaySourceSHA != input.GatewaySourceSHA ||
		input.Metadata.ControlRepository != registration.Repository.Name() ||
		input.Metadata.RunnerName != registration.RunnerName {
		zeroBytes(registration.RegistrationToken)
		zeroBytes(registration.RemovalToken)
		return preparedInput{}, installerError("installation-metadata-invalid")
	}
	metadata, err := installmetadata.MarshalCanonical(input.Metadata)
	if err != nil {
		zeroBytes(registration.RegistrationToken)
		zeroBytes(registration.RemovalToken)
		return preparedInput{}, installerError("installation-metadata-invalid")
	}
	return preparedInput{
		specification:    cloneSpecification(input.Specification),
		gatewaySourceSHA: input.GatewaySourceSHA,
		brokerImage:      append([]byte(nil), input.BrokerImage...),
		controlImage:     append([]byte(nil), input.ControlImage...),
		runnerImage:      input.RunnerImage, runnerRegistration: registration, metadata: metadata,
	}, nil
}

func cloneRegistration(request runnerregistration.Request) runnerregistration.Request {
	request.RegistrationToken = append([]byte(nil), request.RegistrationToken...)
	request.RemovalToken = append([]byte(nil), request.RemovalToken...)
	return request
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
