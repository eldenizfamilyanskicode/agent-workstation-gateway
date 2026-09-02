package brokersession

import (
	"context"
	"fmt"
	"time"

	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionpolicy"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/executionrun"
	"github.com/eldenizfamilyanskicode/agent-workstation-gateway/internal/installconfig"
)

const (
	defaultRequestReadTimeout     = 30 * time.Second
	defaultResponseWriteTimeout   = 30 * time.Minute
	defaultAcknowledgementTimeout = 30 * time.Second
	maxRequestReadTimeout         = 5 * time.Minute
	maxResponseWriteTimeout       = time.Hour
	maxAcknowledgementTimeout     = 5 * time.Minute
)

// ContextTransport lets the session apply fixed deadlines to every underlying
// native I/O operation without accepting a deadline from request data.
type ContextTransport interface {
	ReadContext(context.Context, []byte) (int, error)
	WriteContext(context.Context, []byte) (int, error)
}

type Options struct {
	RequestReadTimeout     time.Duration
	ResponseWriteTimeout   time.Duration
	AcknowledgementTimeout time.Duration
}

type Session struct {
	configuration          installconfig.Config
	safeBaseEnvironment    []string
	resolver               executionpolicy.Resolver
	runner                 *executionrun.Runner
	gatewaySourceSHA       string
	requestReadTimeout     time.Duration
	responseWriteTimeout   time.Duration
	acknowledgementTimeout time.Duration
}

type Error struct {
	Rule string
}

func (failure *Error) Error() string {
	return fmt.Sprintf("broker session failed: %s", failure.Rule)
}

func sessionError(rule string) error {
	return &Error{Rule: rule}
}
