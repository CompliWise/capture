package installer

import (
	"errors"
	"fmt"
)

// CodedError carries a deployment report error code and operator-safe message.
type CodedError struct {
	Code    string
	Message string
}

func (e *CodedError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// NewCodedError builds a typed installer failure for deployment reporting.
func NewCodedError(code, message string) *CodedError {
	return &CodedError{
		Code:    code,
		Message: message,
	}
}

// ErrorCode returns the deployment error code when err is a CodedError.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var coded *CodedError
	if errors.As(err, &coded) && coded.Code != "" {
		return coded.Code
	}
	return "ERR_INSTALL_FAILED"
}

// ErrorMessage returns a safe operator message for deployment reports.
func ErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}
