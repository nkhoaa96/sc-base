package transport

import (
	"context"

	"dev.azure.com/vib-lz-devops/B08-DSC-Project-SmartCollection/_git/smartcollection-base-go.git/log"
)

// ErrorHandler receives a transport error to be processed for diagnostic purposes.
// Usually this means logging the error.
type ErrorHandler interface {
	Handle(ctx context.Context, err error)
}

// LogErrorHandler is a transport error handler implementation which logs an error.
type LogErrorHandler struct {
	logger log.Logger
}

func NewLogErrorHandler(logger log.Logger) *LogErrorHandler {
	return &LogErrorHandler{
		logger: logger,
	}
}

func (h *LogErrorHandler) Handle(ctx context.Context, err error) {
	h.logger.Log("err", err)
}

// The ErrorHandlerFunc type is an adapter to allow the use of
// ordinary function as ErrorHandler. If f is a function
// with the appropriate signature, ErrorHandlerFunc(f) is a
// ErrorHandler that calls f.
type ErrorHandlerFunc func(ctx context.Context, err error)

// Handle calls f(ctx, err).
func (f ErrorHandlerFunc) Handle(ctx context.Context, err error) {
	f(ctx, err)
}
