package protocol

import "fmt"

// ErrorCode 是供 SDK 和调用方判断校验失败原因的稳定错误码。
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

// ValidationError 指明校验失败的字段与原因，并可保留底层错误。
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
