package protocol

import "fmt"

type ErrorCode string

const (
	ErrInvalidPayload             ErrorCode = "invalid_payload"
	ErrUnsupportedFormat          ErrorCode = "unsupported_format"
	ErrInvalidSignature           ErrorCode = "invalid_signature"
	ErrUnknownKey                 ErrorCode = "unknown_key"
	ErrAppMismatch                ErrorCode = "app_mismatch"
	ErrMachineIdentityUnavailable ErrorCode = "machine_identity_unavailable"
	ErrMachineMismatch            ErrorCode = "machine_mismatch"
	ErrInstanceMismatch           ErrorCode = "instance_mismatch"
	ErrVersionMismatch            ErrorCode = "version_mismatch"
	ErrNotYetValid                ErrorCode = "not_yet_valid"
	ErrExpired                    ErrorCode = "expired"
	ErrClockRollback              ErrorCode = "clock_rollback_suspected"
)

type ValidationError struct {
	Code  ErrorCode
	Field string
	Cause error
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Field)
}
func (e *ValidationError) Unwrap() error { return e.Cause }
func NewValidationError(code ErrorCode, field string, cause error) error {
	return &ValidationError{Code: code, Field: field, Cause: cause}
}
func CodeOf(err error) ErrorCode {
	for err != nil {
		if typed, ok := err.(*ValidationError); ok {
			return typed.Code
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = unwrapper.Unwrap()
	}
	return ""
}
