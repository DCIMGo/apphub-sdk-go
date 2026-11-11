package protocol

import (
	"encoding/json"
	"time"

	"github.com/DCIMGo/apphub-sdk-go/machineidentity"
)

const SchemaVersionV1 = "1.0"

type Mode string

const (
	ModeOffline      Mode = "offline"
	ModeActivateOnce Mode = "activate_once"
	ModeOnlineLease  Mode = "online_lease"
)

type LocalState string

const (
	StateUnlicensed             LocalState = "unlicensed"
	StateActive                 LocalState = "active"
	StateNotYetValid            LocalState = "not_yet_valid"
	StateExpiring               LocalState = "expiring"
	StateExpired                LocalState = "expired"
	StateInvalidSignature       LocalState = "invalid_signature"
	StateFileCorrupted          LocalState = "file_corrupted"
	StateAppMismatch            LocalState = "app_mismatch"
	StateMachineMismatch        LocalState = "machine_mismatch"
	StateInstanceMismatch       LocalState = "instance_mismatch"
	StateVersionMismatch        LocalState = "version_mismatch"
	StateUnsupportedFormat      LocalState = "unsupported_format"
	StateClockRollbackSuspected LocalState = "clock_rollback_suspected"
)

type LeaseState string

const (
	LeaseUnlicensed  LeaseState = "unlicensed"
	LeaseAuthorizing LeaseState = "authorizing"
	LeaseAuthorized  LeaseState = "authorized"
	LeaseRenewing    LeaseState = "renewing"
	LeaseGrace       LeaseState = "grace"
	LeaseRestricted  LeaseState = "restricted"
	LeaseRevoked     LeaseState = "revoked"
	LeaseDenied      LeaseState = "denied"
	LeaseExpired     LeaseState = "expired"
)

type GraceEndPolicy string

const (
	GraceReadOnly       GraceEndPolicy = "read_only"
	GraceFeatureDegrade GraceEndPolicy = "feature_degrade"
	GraceDeny           GraceEndPolicy = "deny"
	GraceWarnOnly       GraceEndPolicy = "warn_only"
)

type VersionRange struct {
	Minimum          string `json:"minimum,omitempty"`
	MaximumExclusive string `json:"maximumExclusive,omitempty"`
}
type Entitlements struct {
	Features map[string]bool            `json:"features,omitempty"`
	Limits   map[string]int64           `json:"limits,omitempty"`
	Configs  map[string]json.RawMessage `json:"configs,omitempty"`
}
type UpdatePolicy struct {
	Enabled             bool       `json:"enabled"`
	AutoUpdateEnabled   bool       `json:"autoUpdateEnabled,omitempty"`
	Channels            []string   `json:"channels,omitempty"`
	MaintenanceUntil    *time.Time `json:"maintenanceUntil,omitempty"`
	MaximumVersion      string     `json:"maximumVersion,omitempty"`
	AllowRollback       bool       `json:"allowRollback"`
	ForcedUpdateAllowed bool       `json:"forcedUpdateAllowed,omitempty"`
}
type Payload struct {
	SchemaVersion     string                   `json:"schemaVersion"`
	LicenseID         string                   `json:"licenseId"`
	LicenseItemID     string                   `json:"licenseItemId"`
	LicenseRevision   int64                    `json:"licenseRevision"`
	AppID             string                   `json:"appId"`
	InstanceID        string                   `json:"instanceId"`
	MachineID         string                   `json:"machineId"`
	MachineBinding    *machineidentity.Binding `json:"machineBinding,omitempty"`
	AuthorizationMode Mode                     `json:"authorizationMode"`
	IssuedAt          time.Time                `json:"issuedAt"`
	NotBefore         time.Time                `json:"notBefore"`
	ExpiresAt         *time.Time               `json:"expiresAt,omitempty"`
	VersionRange      VersionRange             `json:"versionRange"`
	Entitlements      Entitlements             `json:"entitlements"`
	UpdatePolicy      UpdatePolicy             `json:"updatePolicy"`
}
type LeasePayload struct {
	SchemaVersion    string                   `json:"schemaVersion"`
	AuthorizationID  string                   `json:"authorizationId"`
	LeaseID          string                   `json:"leaseId"`
	Revision         int64                    `json:"revision"`
	LicenseItemID    string                   `json:"licenseItemId"`
	LicenseRevision  int64                    `json:"licenseRevision"`
	AppID            string                   `json:"appId"`
	InstanceID       string                   `json:"instanceId"`
	MachineID        string                   `json:"machineId"`
	MachineBinding   *machineidentity.Binding `json:"machineBinding,omitempty"`
	Status           LeaseState               `json:"status"`
	IssuedAt         time.Time                `json:"issuedAt"`
	RenewAfter       time.Time                `json:"renewAfter"`
	ExpiresAt        time.Time                `json:"expiresAt"`
	GraceUntil       time.Time                `json:"graceUntil"`
	LicenseExpiresAt *time.Time               `json:"licenseExpiresAt,omitempty"`
	GraceEndPolicy   GraceEndPolicy           `json:"graceEndPolicy"`
	VersionRange     VersionRange             `json:"versionRange"`
	Entitlements     Entitlements             `json:"entitlements"`
	UpdatePolicy     UpdatePolicy             `json:"updatePolicy"`
}
type Status struct {
	Mode            Mode           `json:"mode,omitempty"`
	LocalState      LocalState     `json:"localState,omitempty"`
	LeaseState      LeaseState     `json:"leaseState,omitempty"`
	AppID           string         `json:"appId,omitempty"`
	InstanceID      string         `json:"instanceId,omitempty"`
	LicenseID       string         `json:"licenseId,omitempty"`
	LicenseRevision int64          `json:"licenseRevision,omitempty"`
	LeaseID         string         `json:"leaseId,omitempty"`
	LeaseRevision   int64          `json:"leaseRevision,omitempty"`
	NotBefore       *time.Time     `json:"notBefore,omitempty"`
	ExpiresAt       *time.Time     `json:"expiresAt,omitempty"`
	RenewAfter      *time.Time     `json:"renewAfter,omitempty"`
	GraceUntil      *time.Time     `json:"graceUntil,omitempty"`
	GraceEndPolicy  GraceEndPolicy `json:"graceEndPolicy,omitempty"`
	Entitlements    Entitlements   `json:"entitlements,omitempty"`
	UpdatePolicy    UpdatePolicy   `json:"updatePolicy,omitempty"`
	Reason          string         `json:"reason,omitempty"`
	VerifiedAt      time.Time      `json:"verifiedAt"`
}
