package protocol

import (
	"encoding/json"
	"strings"
	"time"
)

// VerifyOptions 保存授权校验使用的本地应用、机器、实例和时钟信息。
type VerifyOptions struct {
	AppID, AppVersion, MachineID, InstanceID string
	Now                                      time.Time
	ExpiringBefore                           time.Duration
}

// ValidatePayload 校验已验签的本地授权与运行环境是否匹配。
func ValidatePayload(payload Payload, options VerifyOptions) (Status, error) {
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	status := Status{Mode: payload.AuthorizationMode, AppID: payload.AppID, InstanceID: payload.InstanceID, LicenseID: payload.LicenseID, LicenseRevision: payload.LicenseRevision, NotBefore: timePointer(payload.NotBefore), ExpiresAt: payload.ExpiresAt, Entitlements: cloneEntitlements(payload.Entitlements), UpdatePolicy: payload.UpdatePolicy, VerifiedAt: now}
	if payload.SchemaVersion != SchemaVersionV1 && payload.SchemaVersion != SchemaVersionV2 {
		status.LocalState = StateUnsupportedFormat
		return status, NewValidationError(ErrUnsupportedFormat, "schemaVersion", nil)
	}
	if payload.AuthorizationMode != ModeOffline && payload.AuthorizationMode != ModeActivateOnce {
		status.LocalState = StateFileCorrupted
		return status, NewValidationError(ErrInvalidPayload, "authorizationMode", nil)
	}
	if strings.TrimSpace(payload.AppID) == "" || strings.TrimSpace(payload.InstanceID) == "" || strings.TrimSpace(payload.LicenseID) == "" || payload.LicenseRevision < 1 || !ValidMachineBinding(payload.SchemaVersion, payload.MachineID, payload.MachineBinding) {
		status.LocalState = StateFileCorrupted
		return status, NewValidationError(ErrInvalidPayload, "identity", nil)
	}
	if payload.IssuedAt.IsZero() || payload.NotBefore.IsZero() {
		status.LocalState = StateFileCorrupted
		return status, NewValidationError(ErrInvalidPayload, "time", nil)
	}
	if payload.ExpiresAt != nil && !payload.NotBefore.Before(*payload.ExpiresAt) {
		status.LocalState = StateFileCorrupted
		return status, NewValidationError(ErrInvalidPayload, "expiresAt", nil)
	}
	if payload.AppID != options.AppID {
		status.LocalState = StateAppMismatch
		return status, NewValidationError(ErrAppMismatch, "appId", nil)
	}
	if payload.MachineID != options.MachineID {
		status.LocalState = StateMachineMismatch
		return status, NewValidationError(ErrMachineMismatch, "machineId", nil)
	}
	if (payload.AuthorizationMode == ModeOffline || payload.SchemaVersion == SchemaVersionV2) && payload.InstanceID != options.InstanceID {
		status.LocalState = StateInstanceMismatch
		return status, NewValidationError(ErrInstanceMismatch, "instanceId", nil)
	}
	if err := ValidateVersionRange(options.AppVersion, payload.VersionRange); err != nil {
		status.LocalState = StateVersionMismatch
		return status, err
	}
	if now.Before(payload.NotBefore.UTC()) {
		status.LocalState = StateNotYetValid
		return status, NewValidationError(ErrNotYetValid, "notBefore", nil)
	}
	if payload.ExpiresAt != nil && !now.Before(payload.ExpiresAt.UTC()) {
		status.LocalState = StateExpired
		return status, NewValidationError(ErrExpired, "expiresAt", nil)
	}
	status.LocalState = StateActive
	if payload.ExpiresAt != nil && options.ExpiringBefore > 0 && !now.Add(options.ExpiringBefore).Before(payload.ExpiresAt.UTC()) {
		status.LocalState = StateExpiring
	}
	return status, nil
}

// ValidateLease 校验已验签的租约，并按签名时间窗计算当前状态。
func ValidateLease(payload LeasePayload, options VerifyOptions) (Status, error) {
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	status := Status{Mode: ModeOnlineLease, AppID: payload.AppID, InstanceID: payload.InstanceID, LicenseRevision: payload.LicenseRevision, LeaseID: payload.LeaseID, LeaseRevision: payload.Revision, ExpiresAt: timePointer(payload.ExpiresAt), RenewAfter: timePointer(payload.RenewAfter), GraceUntil: timePointer(payload.GraceUntil), GraceEndPolicy: payload.GraceEndPolicy, Entitlements: cloneEntitlements(payload.Entitlements), UpdatePolicy: payload.UpdatePolicy, VerifiedAt: now}
	if payload.SchemaVersion != SchemaVersionV1 && payload.SchemaVersion != SchemaVersionV2 {
		status.LeaseState = LeaseDenied
		return status, NewValidationError(ErrUnsupportedFormat, "schemaVersion", nil)
	}
	if payload.AppID != options.AppID {
		status.LeaseState = LeaseDenied
		return status, NewValidationError(ErrAppMismatch, "appId", nil)
	}
	if payload.MachineID != options.MachineID || !ValidMachineBinding(payload.SchemaVersion, payload.MachineID, payload.MachineBinding) {
		status.LeaseState = LeaseDenied
		return status, NewValidationError(ErrMachineMismatch, "machineId", nil)
	}
	if payload.SchemaVersion == SchemaVersionV2 && payload.InstanceID != options.InstanceID {
		status.LeaseState = LeaseDenied
		status.Reason = string(ErrInstanceMismatch)
		return status, NewValidationError(ErrInstanceMismatch, "instanceId", nil)
	}
	if payload.Revision < 1 || payload.LicenseRevision < 1 || payload.LeaseID == "" || payload.InstanceID == "" || payload.IssuedAt.IsZero() || !payload.IssuedAt.Before(payload.RenewAfter) || !payload.RenewAfter.Before(payload.ExpiresAt) || payload.GraceUntil.Before(payload.ExpiresAt) {
		status.LeaseState = LeaseDenied
		return status, NewValidationError(ErrInvalidPayload, "lease", nil)
	}
	if err := ValidateVersionRange(options.AppVersion, payload.VersionRange); err != nil {
		status.LeaseState = LeaseDenied
		return status, err
	}
	switch payload.Status {
	case LeaseRevoked:
		status.LeaseState = LeaseRevoked
		return status, nil
	case LeaseDenied:
		status.LeaseState = LeaseDenied
		return status, nil
	case LeaseRestricted:
		status.LeaseState = LeaseRestricted
		return status, nil
	case LeaseExpired:
		status.LeaseState = LeaseExpired
		return status, nil
	case LeaseAuthorized, LeaseRenewing:
	default:
		status.LeaseState = LeaseDenied
		return status, NewValidationError(ErrInvalidPayload, "status", nil)
	}
	if payload.LicenseExpiresAt != nil && !now.Before(payload.LicenseExpiresAt.UTC()) {
		status.LeaseState = LeaseExpired
		return status, nil
	}
	switch {
	case now.Before(payload.RenewAfter.UTC()):
		status.LeaseState = LeaseAuthorized
	case now.Before(payload.ExpiresAt.UTC()):
		status.LeaseState = LeaseRenewing
	case now.Before(payload.GraceUntil.UTC()):
		status.LeaseState = LeaseGrace
	default:
		status.LeaseState = LeaseRestricted
	}
	return status, nil
}
func timePointer(value time.Time) *time.Time { result := value.UTC(); return &result }
func cloneEntitlements(source Entitlements) Entitlements {
	result := Entitlements{Features: make(map[string]bool, len(source.Features)), Limits: make(map[string]int64, len(source.Limits)), Configs: make(map[string]json.RawMessage, len(source.Configs))}
	for key, value := range source.Features {
		result.Features[key] = value
	}
	for key, value := range source.Limits {
		result.Limits[key] = value
	}
	for key, value := range source.Configs {
		result.Configs[key] = append([]byte(nil), value...)
	}
	return result
}
