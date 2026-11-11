// Package apphubsdk provides local and online authorization for DCIMGo apps.
package apphubsdk

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"time"
)

const Version = "0.1.0"

type Client interface {
	MachineID(context.Context) (string, error)
	MachineRequest(context.Context) ([]byte, error)
	ImportLicense(context.Context, []byte) (*Status, error)
	ActivateOnce(context.Context, ActivateRequest) (*Status, error)
	AuthorizeOnline(context.Context, AuthorizeRequest) (*Status, error)
	RenewOnline(context.Context) (*Status, error)
	CheckUpdate(context.Context, UpdateCheckRequest) (*UpdateCheckResult, error)
	StartAutoRenew(context.Context) error
	StopAutoRenew()
	VerifyLocal(context.Context) (*Status, error)
	VerifyOnlineLease(context.Context) (*Status, error)
	Status() Status
	HasFeature(string) bool
	GetIntLimit(string) (int64, bool)
	GetConfig(string) (any, bool)
}

type MachineSource interface {
	Components(context.Context) ([]string, error)
}

type Config struct {
	AppID         string
	AppVersion    string
	InstanceID    string
	ServerURL     string
	LicensePath   string
	PublicKeys    map[string]ed25519.PublicKey
	MachineSource MachineSource
	// UseUnifiedMachineIdentity opts in to schema 2.0 for new requests.
	// Verification chooses the identity from the signed file or lease.
	UseUnifiedMachineIdentity bool
	HTTPClient                *http.Client
	Clock                     func() time.Time
	ExpiringBefore            time.Duration
	ClockRollbackSkew         time.Duration
	AutoRenewInterval         time.Duration
	// InstanceCredential is the short-lived credential issued for update checks.
	InstanceCredential string
}

type ActivateRequest struct {
	ActivationCode string
	ServerURL      string
	InstanceID     string
	InstanceName   string
	IdempotencyKey string
}

type AuthorizeRequest struct {
	ActivationCode string
	ServerURL      string
	InstanceID     string
	InstanceName   string
	IdempotencyKey string
}

// UpdateCheckRequest describes the target runtime for an update lookup. Empty
// values use the SDK configuration (and the stable channel/current platform).
type UpdateCheckRequest struct {
	ServerURL          string
	CurrentVersion     string
	Channel            string
	OS                 string
	Arch               string
	InstanceID         string
	InstanceCredential string
	IdempotencyKey     string
}

// UpdateCheckResult is the server's entitlement-aware update decision.
// Release is nil when no update is available or the request is denied.
type UpdateCheckResult struct {
	UpdateAvailable        bool
	Reason                 string
	UpdateTaskID           string
	Release                *UpdateRelease
	DownloadToken          string
	DownloadTokenExpiresAt *time.Time
}

// UpdateRelease contains safe release metadata needed by an updater to decide
// whether to fetch a manifest. Package bytes are never returned here.
type UpdateRelease struct {
	ID               string
	Version          string
	Channel          string
	Mandatory        bool
	SecurityUpdate   bool
	SupportsRollback bool
	ReleaseNotes     string
	KnownIssues      string
	MaintenanceUntil *time.Time
	ManifestURL      string
	ManifestSHA256   string
}

type Status struct {
	Mode            string
	LocalState      string
	LeaseState      string
	AppID           string
	InstanceID      string
	LicenseID       string
	LicenseRevision int64
	LeaseID         string
	LeaseRevision   int64
	NotBefore       *time.Time
	ExpiresAt       *time.Time
	RenewAfter      *time.Time
	GraceUntil      *time.Time
	GraceEndPolicy  string
	Features        map[string]bool
	Limits          map[string]int64
	Configs         map[string]json.RawMessage
	UpdatePolicy    UpdatePolicy
	Reason          string
	VerifiedAt      time.Time
}

type UpdatePolicy struct {
	Enabled             bool
	AutoUpdateEnabled   bool
	Channels            []string
	MaintenanceUntil    *time.Time
	MaximumVersion      string
	AllowRollback       bool
	ForcedUpdateAllowed bool
}

type APIError struct {
	HTTPStatus int
	Code       int
	Reason     string
	Message    string
	TraceID    string
}

func (e *APIError) Error() string {
	if e.Reason != "" {
		return "AppHub request failed: " + e.Reason
	}
	return "AppHub request failed"
}
