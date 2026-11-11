package apphubsdk

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"
)

// updateCheckResponse mirrors the public SDK update/check response. Release
// metadata is intentionally flat in the wire contract so clients can render a
// decision without downloading a manifest first.
type updateCheckResponse struct {
	UpdateAvailable        bool       `json:"updateAvailable"`
	Reason                 string     `json:"reason"`
	UpdateTaskID           string     `json:"updateTaskId"`
	ReleaseID              string     `json:"releaseId"`
	Version                string     `json:"version"`
	Channel                string     `json:"channel"`
	Mandatory              bool       `json:"mandatory"`
	SecurityUpdate         bool       `json:"securityUpdate"`
	SupportsRollback       bool       `json:"supportsRollback"`
	ReleaseNotes           string     `json:"releaseNotes"`
	KnownIssues            string     `json:"knownIssues"`
	MaintenanceUntil       *time.Time `json:"maintenanceUntil"`
	ManifestURL            string     `json:"manifestUrl"`
	ManifestSHA256         string     `json:"manifestSha256"`
	DownloadToken          string     `json:"downloadToken"`
	DownloadTokenExpiresAt *time.Time `json:"downloadTokenExpiresAt"`
}

// CheckUpdate asks AppHub whether the configured instance is entitled to a
// published update. It does not download or install anything; callers should
// verify the returned manifest and hand the package to an updater agent.
func (c *client) CheckUpdate(ctx context.Context, request UpdateCheckRequest) (*UpdateCheckResult, error) {
	c.requestLock.Lock()
	defer c.requestLock.Unlock()

	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	server, instanceID, idempotencyKey, err := c.prepareOnline(request.ServerURL, request.InstanceID, request.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	currentVersion := strings.TrimSpace(request.CurrentVersion)
	if currentVersion == "" {
		currentVersion = c.config.AppVersion
	}
	if currentVersion == "" {
		return nil, fmt.Errorf("currentVersion is required")
	}
	channel := strings.TrimSpace(request.Channel)
	if channel == "" {
		channel = "stable"
	}
	osName := strings.TrimSpace(request.OS)
	if osName == "" {
		osName = runtime.GOOS
	}
	arch := strings.TrimSpace(request.Arch)
	if arch == "" {
		arch = runtime.GOARCH
	}
	credential := request.InstanceCredential
	if credential == "" {
		credential = c.config.InstanceCredential
	}
	machine, err := c.MachineID(ctx)
	if err != nil {
		return nil, err
	}
	metadata, err := newRequestMetadata(c.config.Clock)
	if err != nil {
		return nil, err
	}
	body := struct {
		ProtocolVersion    string    `json:"protocolVersion"`
		SDKVersion         string    `json:"sdkVersion"`
		AppID              string    `json:"appId"`
		CurrentVersion     string    `json:"currentVersion"`
		Channel            string    `json:"channel"`
		OS                 string    `json:"os"`
		Arch               string    `json:"arch"`
		MachineID          string    `json:"machineId"`
		InstanceID         string    `json:"instanceId"`
		InstanceCredential string    `json:"instanceCredential,omitempty"`
		RequestID          string    `json:"requestId"`
		Timestamp          time.Time `json:"timestamp"`
		Nonce              string    `json:"nonce"`
	}{
		protocolVersion, Version, c.config.AppID, currentVersion, channel, osName, arch,
		machine, instanceID, credential, metadata.requestID, metadata.timestamp, metadata.nonce,
	}
	var response updateCheckResponse
	if err := c.postJSON(ctx, server, "/api/v1/update/check", idempotencyKey, body, &response); err != nil {
		return nil, err
	}
	result := &UpdateCheckResult{
		UpdateAvailable:        response.UpdateAvailable,
		Reason:                 response.Reason,
		UpdateTaskID:           response.UpdateTaskID,
		DownloadToken:          response.DownloadToken,
		DownloadTokenExpiresAt: response.DownloadTokenExpiresAt,
	}
	if response.ReleaseID != "" || response.Version != "" {
		result.Release = &UpdateRelease{
			ID: response.ReleaseID, Version: response.Version, Channel: response.Channel,
			Mandatory: response.Mandatory, SecurityUpdate: response.SecurityUpdate,
			SupportsRollback: response.SupportsRollback, ReleaseNotes: response.ReleaseNotes,
			KnownIssues: response.KnownIssues, MaintenanceUntil: response.MaintenanceUntil,
			ManifestURL: response.ManifestURL, ManifestSHA256: response.ManifestSHA256,
		}
	}
	return result, nil
}
