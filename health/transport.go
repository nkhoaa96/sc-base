package health

import (
	"dev.azure.com/vib-lz-devops/B08-DSC-Project-SmartCollection/_git/smartcollection-base-go.git/transport"
	"net/http"

	"context"
	"encoding/json"

	golog "dev.azure.com/vib-lz-devops/B08-DSC-Project-SmartCollection/_git/smartcollection-base-go.git/log"
	gotransport "dev.azure.com/vib-lz-devops/B08-DSC-Project-SmartCollection/_git/smartcollection-base-go.git/transport/http"

	"github.com/gorilla/mux"
)

// errorer describes the behavior of a request or response that can contain errors
type errorer interface {
	error() error
}

// MakeHandler builds a go-base http transport and returns it
func MakeHandler(logger golog.Logger, prefix string) http.Handler {
	options := []gotransport.ServerOption{
		gotransport.ServerErrorEncoder(errorEncoder),
		gotransport.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
	}

	e := makeHealthCheckEndpoint()

	healthHandler := gotransport.NewServer(
		e,
		decodeHealthCheckRequest,
		encodeHealthCheckResponse,
		options...,
	)

	r := mux.NewRouter()
	r.Handle(prefix+"/v1/health", healthHandler).Methods("GET")
	return r
}
func errorEncoder(_ context.Context, err error, w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
}

// ErrorResponse ...
type ErrorResponse struct {
	Error string `json:"error"`
}

// decodeHealthCheckRequest returns an empty healthCheck request because there are no params for this request
func decodeHealthCheckRequest(_ context.Context, r *http.Request) (interface{}, error) {
	return healthCheckRequest{}, nil
}

// encodeHealthCheckResponse encodes any errors received from handling the request and returns
func encodeHealthCheckResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		encodeError(ctx, e.error(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

// encodeError writes error headers if an error was received from a health check
func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": err.Error(),
	})
}
