package authn

import (
	"fmt"
	"strings"
)

// Account is an AuthN user account
type Account struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Locked   bool   `json:"locked"`
	Deleted  bool   `json:"deleted"`
}

// FieldError is a returned for each field in an API
// request that does not match the expectations. Examples
// are MISSING, TAKEN, INSECURE, ...
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// String returns a string representation of f
// and implements fmt.Stringer
func (f FieldError) String() string {
	return fmt.Sprintf("%s: %s", f.Field, f.Message)
}

// ErrorResponse is returned together with 4xx and 5xx HTTP status
// codes and contains a list of error conditions encountered while
// processing an API request
// It implements the error interface
type ErrorResponse struct {
	StatusCode int          `json:"-"`
	URL        string       `json:"-"`
	Errors     []FieldError `json:"errors"`
}

// Error implements the error interface
func (e *ErrorResponse) Error() string {
	msgs := make([]string, len(e.Errors))

	for idx, field := range e.Errors {
		msgs[idx] = field.String()
	}

	return fmt.Sprintf("received %d from %s. Errors in %s", e.StatusCode, e.URL, strings.Join(msgs, "; "))
}

// HasField returns true if field caused an error
func (e *ErrorResponse) HasField(field string) bool {
	for _, f := range e.Errors {
		if f.Field == field {
			return true
		}
	}
	return false
}

// Field returns the error message for field if any
func (e *ErrorResponse) Field(field string) (string, bool) {
	for _, f := range e.Errors {
		if f.Field == field {
			return f.Message, true
		}
	}

	return "", false
}
