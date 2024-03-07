// Package errors provides a way to return detailed information
// for an RPC request error. The error is normally JSON encoded.
package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Error implements the error interface.
type Error struct {
	Id     string `json:"id"`
	Code   int32  `json:"code"`
	Detail string `json:"detail"`
	Status string `json:"status"`
}

func (e *Error) Error() string {
	b, _ := json.Marshal(e)
	return string(b)
}

// New generates a custom error.
func New(id, detail string, code int32) error {
	return &Error{
		Id:     id,
		Code:   code,
		Detail: detail,
		Status: http.StatusText(int(code)),
	}
}

// Parse tries to parse a JSON string into an error. If that
// fails, it will set the given string as the error detail.
func Parse(err string) *Error {
	e := new(Error)
	errr := json.Unmarshal([]byte(err), e)
	if errr != nil {
		e.Detail = err
	}
	return e
}

//SS Error
func SmartSalesError(a ...interface{}) error {
	return &Error{
		Id:     "200",
		Code:   200,
		Detail: fmt.Sprintf("%s", a...),
		Status: http.StatusText(200),
	}
}

// BadRequest generates a 400 error.
func BadRequest(a ...interface{}) error {
	return &Error{
		Id:     "400",
		Code:   400,
		Detail: fmt.Sprintf("%s", a...),
		Status: http.StatusText(400),
	}
}

// Unauthorized generates a 401 error.
func Unauthorized(a ...interface{}) error {
	return &Error{
		Id:     "401",
		Code:   401,
		Detail: fmt.Sprintf("%s", a...),
		Status: http.StatusText(401),
	}
}

// Forbidden generates a 403 error.
func Forbidden(a ...interface{}) error {
	return &Error{
		Id:     "403",
		Code:   403,
		Detail: fmt.Sprintf("%s", a...),
		Status: http.StatusText(403),
	}
}

// NotFound generates a 404 error.
func NotFound(a ...interface{}) error {
	return &Error{
		Id:     "404",
		Code:   404,
		Detail: fmt.Sprintf("%s", a...),
		Status: http.StatusText(404),
	}
}

// MethodNotAllowed generates a 405 error.
func MethodNotAllowed(a ...interface{}) error {
	return &Error{
		Id:     "405",
		Code:   405,
		Detail: fmt.Sprintf("%s", a...),
		Status: http.StatusText(405),
	}
}

// Timeout generates a 408 error.
func Timeout(a ...interface{}) error {
	return &Error{
		Id:     "408",
		Code:   408,
		Detail: fmt.Sprintf("%s", a...),
		Status: http.StatusText(408),
	}
}

// Conflict generates a 409 error.
func Conflict(a ...interface{}) error {
	return &Error{
		Id:     "409",
		Code:   409,
		Detail: fmt.Sprintf("%s", a...),
		Status: http.StatusText(409),
	}
}

// InternalServerError generates a 500 error.
func InternalServerError(a ...interface{}) error {
	return &Error{
		Id:     "500",
		Code:   502,
		Detail: fmt.Sprintf("%s", a...),
		Status: http.StatusText(502),
	}
}
