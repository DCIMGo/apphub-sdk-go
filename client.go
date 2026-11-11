package apphubsdk

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	license "github.com/DCIMGo/apphub-sdk-go/internal/protocol"
	licensefile "github.com/DCIMGo/apphub-sdk-go/internal/protocol"
	"github.com/DCIMGo/apphub-sdk-go/machineidentity"
)

type client struct {
	config Config
	keys   licensefile.KeySet

	mu          sync.RWMutex
	status      Status
	serverURL   string
	autoCancel  context.CancelFunc
	autoDone    chan struct{}
	requestLock sync.Mutex
}

func New(config Config) (Client, error) {
	if !validAppID(config.AppID) || config.AppVersion == "" || config.LicensePath == "" || len(config.PublicKeys) == 0 {
		return nil, fmt.Errorf("appId, appVersion, licensePath, and publicKeys are required")
	}
	if err := license.ValidateVersionRange(config.AppVersion, license.VersionRange{}); err != nil {
		return nil, fmt.Errorf("invalid appVersion: %w", err)
	}
	if config.InstanceID == "" {
		config.InstanceID = "default"
	}
	if len(config.InstanceID) > 100 {
		return nil, fmt.Errorf("instanceId exceeds 100 characters")
	}
	if config.ServerURL != "" {
		if _, err := validateServerURL(config.ServerURL); err != nil {
			return nil, err
		}
	}
	if config.MachineSource == nil {
		config.MachineSource = hostMachineSource{}
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.ExpiringBefore == 0 {
		config.ExpiringBefore = 30 * 24 * time.Hour
	}
	if config.ClockRollbackSkew == 0 {
		config.ClockRollbackSkew = 5 * time.Minute
	}
	if config.AutoRenewInterval == 0 {
		config.AutoRenewInterval = time.Minute
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	httpClient := *config.HTTPClient
	callerRedirect := httpClient.CheckRedirect
	httpClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if err := secureRedirect(request, via); err != nil {
			return err
		}
		if callerRedirect != nil {
			return callerRedirect(request, via)
		}
		return nil
	}
	config.HTTPClient = &httpClient
	keys := make(licensefile.KeySet, len(config.PublicKeys))
	for keyID, publicKey := range config.PublicKeys {
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid public key %q", keyID)
		}
		keys[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return &client{
		config:    config,
		keys:      keys,
		serverURL: strings.TrimRight(config.ServerURL, "/"),
		status:    Status{LocalState: string(license.StateUnlicensed), LeaseState: string(license.LeaseUnlicensed)},
	}, nil
}

func (c *client) MachineID(ctx context.Context) (string, error) {
	if err := requireContext(ctx); err != nil {
		return "", err
	}
	id, _, err := c.requestMachineIdentity(ctx)
	return id, err
}

func (c *client) MachineRequest(ctx context.Context) ([]byte, error) {
	if err := requireContext(ctx); err != nil {
		return nil, err
	}
	if c.config.UseUnifiedMachineIdentity {
		identity, err := machineidentity.Collect(ctx)
		if err != nil {
			return nil, err
		}
		return identity.MarshalRequest(c.config.AppID, c.config.AppVersion, c.config.InstanceID, c.config.Clock())
	}
	machine, err := c.MachineID(ctx)
	if err != nil {
		return nil, err
	}
	request := struct {
		SchemaVersion string    `json:"schemaVersion"`
		AppID         string    `json:"appId"`
		MachineID     string    `json:"machineId"`
		GeneratedAt   time.Time `json:"generatedAt"`
	}{license.SchemaVersionV1, c.config.AppID, machine, c.config.Clock().UTC()}
	content, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal machine request: %w", err)
	}
	return content, nil
}

func (c *client) ImportLicense(ctx context.Context, content []byte) (*Status, error) {
	if err := requireContext(ctx); err != nil {
		return nil, err
	}
	if len(content) == 0 || len(content) > maxLocalArtifactSize {
		return nil, fmt.Errorf("license content is empty or too large")
	}
	now := c.config.Clock().UTC()
	lastSeen, err := c.readClock()
	if err != nil {
		return nil, err
	}
	if !lastSeen.IsZero() && now.Add(c.config.ClockRollbackSkew).Before(lastSeen) {
		status := Status{LocalState: string(license.StateClockRollbackSuspected), Reason: string(license.ErrClockRollback), VerifiedAt: now}
		c.setStatus(status)
		return statusPointer(status), license.NewValidationError(license.ErrClockRollback, "clock", nil)
	}
	status, err := c.verifyLicenseContent(ctx, content, now)
	if err != nil {
		return statusPointer(status), err
	}
	err = atomicWriteValidated(c.config.LicensePath, content, 0o600, func(staged []byte) error {
		_, verifyErr := c.verifyLicenseContent(ctx, staged, now)
		return verifyErr
	})
	if err != nil {
		return nil, err
	}
	if lastSeen.After(now) {
		now = lastSeen
	}
	if err := c.writeClock(now); err != nil {
		return nil, err
	}
	c.setStatus(status)
	return statusPointer(status), nil
}

func (c *client) VerifyLocal(ctx context.Context) (*Status, error) {
	if err := requireContext(ctx); err != nil {
		return nil, err
	}
	content, err := readBoundedFile(c.config.LicensePath)
	if err != nil {
		status := Status{LocalState: string(license.StateUnlicensed), Reason: "license_not_found", VerifiedAt: c.config.Clock().UTC()}
		c.setStatus(status)
		return statusPointer(status), err
	}
	now := c.config.Clock().UTC()
	lastSeen, err := c.readClock()
	if err != nil {
		return nil, err
	}
	if !lastSeen.IsZero() && now.Add(c.config.ClockRollbackSkew).Before(lastSeen) {
		status := Status{LocalState: string(license.StateClockRollbackSuspected), Reason: string(license.ErrClockRollback), VerifiedAt: now}
		c.setStatus(status)
		return statusPointer(status), license.NewValidationError(license.ErrClockRollback, "clock", nil)
	}
	status, err := c.verifyLicenseContent(ctx, content, now)
	c.setStatus(status)
	if err != nil {
		return statusPointer(status), err
	}
	if lastSeen.After(now) {
		now = lastSeen
	}
	if err := c.writeClock(now); err != nil {
		return nil, err
	}
	return statusPointer(status), nil
}

func (c *client) verifyLicenseContent(ctx context.Context, content []byte, now time.Time) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	payload, _, err := c.keys.VerifyLicense(content)
	if err != nil {
		state := license.StateFileCorrupted
		switch license.CodeOf(err) {
		case license.ErrInvalidSignature, license.ErrUnknownKey:
			state = license.StateInvalidSignature
		case license.ErrUnsupportedFormat:
			state = license.StateUnsupportedFormat
		}
		return Status{LocalState: string(state), Reason: string(license.CodeOf(err)), VerifiedAt: now}, err
	}
	machine, err := c.machineForBinding(ctx, payload.MachineBinding)
	if err != nil {
		if payload.MachineBinding != nil {
			return Status{LocalState: string(license.StateMachineMismatch), Reason: string(license.CodeOf(err)), VerifiedAt: now}, err
		}
		return Status{}, err
	}
	internalStatus, err := license.ValidatePayload(payload, license.VerifyOptions{
		AppID:          c.config.AppID,
		AppVersion:     c.config.AppVersion,
		MachineID:      machine,
		InstanceID:     c.config.InstanceID,
		Now:            now,
		ExpiringBefore: c.config.ExpiringBefore,
	})
	return exportStatus(internalStatus), err
}

func (c *client) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneStatus(c.status)
}

func (c *client) HasFeature(code string) bool {
	status := c.Status()
	if !statusUsable(status) {
		return false
	}
	return status.Features[code]
}

func (c *client) GetIntLimit(code string) (int64, bool) {
	status := c.Status()
	if !statusUsable(status) {
		return 0, false
	}
	value, exists := status.Limits[code]
	return value, exists
}

func (c *client) GetConfig(code string) (any, bool) {
	status := c.Status()
	if !statusUsable(status) {
		return nil, false
	}
	raw, exists := status.Configs[code]
	if !exists {
		return nil, false
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, false
	}
	return value, true
}

func (c *client) setStatus(status Status) {
	c.mu.Lock()
	c.status = cloneStatus(status)
	c.mu.Unlock()
}

func statusUsable(status Status) bool {
	return status.LocalState == string(license.StateActive) || status.LocalState == string(license.StateExpiring) ||
		status.LeaseState == string(license.LeaseAuthorized) || status.LeaseState == string(license.LeaseRenewing) ||
		status.LeaseState == string(license.LeaseGrace)
}

func (c *client) readClock() (time.Time, error) {
	content, err := os.ReadFile(c.config.LicensePath + ".clock")
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("read verification clock: %w", err)
	}
	value, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(content)))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse verification clock: %w", err)
	}
	return value.UTC(), nil
}

func (c *client) writeClock(value time.Time) error {
	return atomicWrite(c.config.LicensePath+".clock", []byte(value.UTC().Format(time.RFC3339Nano)), 0o600)
}

func validAppID(value string) bool {
	if len(value) < 3 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}

func validateServerURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimRight(value, "/"))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("invalid authorization server URL")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")) {
		return nil, fmt.Errorf("authorization server must use HTTPS")
	}
	return parsed, nil
}

func secureRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return fmt.Errorf("too many redirects")
	}
	if request.URL.Scheme != "https" && request.URL.Hostname() != "localhost" && request.URL.Hostname() != "127.0.0.1" && request.URL.Hostname() != "::1" {
		return fmt.Errorf("redirect to insecure authorization server blocked")
	}
	if len(via) > 0 && (!strings.EqualFold(request.URL.Scheme, via[0].URL.Scheme) || !strings.EqualFold(request.URL.Host, via[0].URL.Host)) {
		return fmt.Errorf("cross-origin authorization redirect blocked")
	}
	return nil
}

func exportStatus(source license.Status) Status {
	return Status{
		Mode:            string(source.Mode),
		LocalState:      string(source.LocalState),
		LeaseState:      string(source.LeaseState),
		AppID:           source.AppID,
		InstanceID:      source.InstanceID,
		LicenseID:       source.LicenseID,
		LicenseRevision: source.LicenseRevision,
		LeaseID:         source.LeaseID,
		LeaseRevision:   source.LeaseRevision,
		NotBefore:       source.NotBefore,
		ExpiresAt:       source.ExpiresAt,
		RenewAfter:      source.RenewAfter,
		GraceUntil:      source.GraceUntil,
		GraceEndPolicy:  string(source.GraceEndPolicy),
		Features:        source.Entitlements.Features,
		Limits:          source.Entitlements.Limits,
		Configs:         source.Entitlements.Configs,
		UpdatePolicy: UpdatePolicy{
			Enabled:             source.UpdatePolicy.Enabled,
			AutoUpdateEnabled:   source.UpdatePolicy.AutoUpdateEnabled,
			Channels:            append([]string(nil), source.UpdatePolicy.Channels...),
			MaintenanceUntil:    source.UpdatePolicy.MaintenanceUntil,
			MaximumVersion:      source.UpdatePolicy.MaximumVersion,
			AllowRollback:       source.UpdatePolicy.AllowRollback,
			ForcedUpdateAllowed: source.UpdatePolicy.ForcedUpdateAllowed,
		},
		Reason:     source.Reason,
		VerifiedAt: source.VerifiedAt,
	}
}

func cloneStatus(status Status) Status {
	status.Features = cloneBoolMap(status.Features)
	status.Limits = cloneIntMap(status.Limits)
	status.Configs = cloneRawMap(status.Configs)
	status.UpdatePolicy.Channels = append([]string(nil), status.UpdatePolicy.Channels...)
	return status
}

func statusPointer(status Status) *Status {
	copy := cloneStatus(status)
	return &copy
}

func cloneBoolMap(source map[string]bool) map[string]bool {
	result := make(map[string]bool, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneIntMap(source map[string]int64) map[string]int64 {
	result := make(map[string]int64, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneRawMap(source map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(source))
	for key, value := range source {
		result[key] = append([]byte(nil), value...)
	}
	return result
}

// requireContext keeps the public SDK methods fail-safe. A nil context is a
// programming error, but returning a regular error is preferable to allowing
// a machine source, HTTP request, or local verifier to panic while an
// application is starting up.
func requireContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	return nil
}
