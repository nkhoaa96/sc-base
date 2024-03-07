package health

import (
	"context"
	"dev.azure.com/vib-lz-devops/B08-DSC-Project-SmartCollection/_git/smartcollection-base-go.git/endpoint"
)

// healthCheckRequest has no parameters, but we still generate an empty struct to represent it
type healthCheckRequest struct{}

// healthCheckResponse represents an HTTP response from the health endpoint containing any errors
type healthCheckResponse struct {
	Error error  `json:"error,omitempty"`
	Msg   string `json:"msg"`
}

// error is an implementation of the errorer interface allowing us to encode errors received from the service
func (r healthCheckResponse) error() error { return r.Error }

// makeHealthEndpoint returns a go-base endpoint, wrapping the health response
func makeHealthCheckEndpoint() endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		return healthCheckResponse{
			Error: nil,
			Msg:   "ok",
		}, nil
	}
}
