package apphubsdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	license "github.com/DCIMGo/apphub-sdk-go/internal/protocol"
	"github.com/DCIMGo/apphub-sdk-go/machineidentity"
)

const protocolVersion = license.SchemaVersionV1

func protocolVersionForBinding(binding *machineidentity.Binding) string {
	if binding != nil {
		return license.SchemaVersionV2
	}
	return protocolVersion
}

type apiResponse[T any] struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    T      `json:"data"`
	TraceID string `json:"traceId"`
}

type apiErrorData struct {
	Reason string `json:"reason"`
}

type activationResponse struct {
	ActivationID    string `json:"activationId"`
	LicenseID       string `json:"licenseId"`
	LicenseItemID   string `json:"licenseItemId"`
	LicenseRevision int64  `json:"licenseRevision"`
	File            struct {
		Name    string `json:"name"`
		Content string `json:"content"`
		Size    int64  `json:"size"`
		SHA256  string `json:"sha256"`
	} `json:"file"`
}

type leaseResponse struct {
	AuthorizationID string `json:"authorizationId"`
	LeaseID         string `json:"leaseId"`
	Revision        int64  `json:"revision"`
	LeaseToken      string `json:"leaseToken"`
	Status          string `json:"status"`
}

type commonOnlineRequest struct {
	ProtocolVersion string                   `json:"protocolVersion"`
	AppID           string                   `json:"appId"`
	AppVersion      string                   `json:"appVersion,omitempty"`
	SDKVersion      string                   `json:"sdkVersion"`
	ActivationCode  string                   `json:"activationCode,omitempty"`
	MachineID       string                   `json:"machineId"`
	MachineBinding  *machineidentity.Binding `json:"machineBinding,omitempty"`
	InstanceID      string                   `json:"instanceId"`
	InstanceName    string                   `json:"instanceName,omitempty"`
	RequestID       string                   `json:"requestId"`
	Timestamp       time.Time                `json:"timestamp"`
	Nonce           string                   `json:"nonce"`
}

// ActivateOnce 校验返回文件的大小和摘要，再交给本地导入流程验签并安装。
func (c *client) ActivateOnce(ctx context.Context, request ActivateRequest) (*Status, error) {
	if err := requireContext(ctx); err != nil {
		return nil, err
	}
	c.requestLock.Lock()
	defer c.requestLock.Unlock()
	server, instanceID, idempotencyKey, err := c.prepareOnline(request.ServerURL, request.InstanceID, request.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	machine, binding, err := c.requestMachineIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if binding != nil && instanceID != c.config.InstanceID {
		return nil, license.NewValidationError(license.ErrInstanceMismatch, "instanceId", nil)
	}
	metadata, err := newRequestMetadata(c.config.Clock)
	if err != nil {
		return nil, err
	}
	body := commonOnlineRequest{
		ProtocolVersion: protocolVersionForBinding(binding),
		MachineBinding:  binding,
		AppID:           c.config.AppID,
		AppVersion:      c.config.AppVersion,
		SDKVersion:      Version,
		ActivationCode:  request.ActivationCode,
		MachineID:       machine,
		InstanceID:      instanceID,
		InstanceName:    request.InstanceName,
		RequestID:       metadata.requestID,
		Timestamp:       metadata.timestamp,
		Nonce:           metadata.nonce,
	}
	var response activationResponse
	if err := c.postJSON(ctx, server, "/api/v1/activation/issue", idempotencyKey, body, &response); err != nil {
		return nil, err
	}
	content, err := decodeEnvelope(response.File.Content)
	if err != nil {
		return nil, fmt.Errorf("decode issued license: %w", err)
	}
	if response.File.Size != int64(len(content)) {
		return nil, fmt.Errorf("issued license size mismatch")
	}
	digest := sha256.Sum256(content)
	if !strings.EqualFold(response.File.SHA256, hex.EncodeToString(digest[:])) {
		return nil, fmt.Errorf("issued license digest mismatch")
	}
	if binding != nil {
		payload, _, err := c.keys.VerifyLicense(content)
		if err != nil {
			return nil, err
		}
		if payload.MachineBinding == nil || *payload.MachineBinding != *binding || payload.AuthorizationMode != license.ModeActivateOnce {
			return nil, license.NewValidationError(license.ErrInvalidPayload, "machineBinding", nil)
		}
	}
	return c.ImportLicense(ctx, content)
}

// AuthorizeOnline 用激活码申请租约，校验返回的签名内容后保存缓存。
func (c *client) AuthorizeOnline(ctx context.Context, request AuthorizeRequest) (*Status, error) {
	if err := requireContext(ctx); err != nil {
		return nil, err
	}
	c.requestLock.Lock()
	defer c.requestLock.Unlock()
	server, instanceID, idempotencyKey, err := c.prepareOnline(request.ServerURL, request.InstanceID, request.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	machine, binding, err := c.requestMachineIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if binding != nil && instanceID != c.config.InstanceID {
		return nil, license.NewValidationError(license.ErrInstanceMismatch, "instanceId", nil)
	}
	metadata, err := newRequestMetadata(c.config.Clock)
	if err != nil {
		return nil, err
	}
	body := commonOnlineRequest{
		ProtocolVersion: protocolVersionForBinding(binding),
		MachineBinding:  binding,
		AppID:           c.config.AppID,
		AppVersion:      c.config.AppVersion,
		SDKVersion:      Version,
		ActivationCode:  request.ActivationCode,
		MachineID:       machine,
		InstanceID:      instanceID,
		InstanceName:    request.InstanceName,
		RequestID:       metadata.requestID,
		Timestamp:       metadata.timestamp,
		Nonce:           metadata.nonce,
	}
	var response leaseResponse
	if err := c.postJSON(ctx, server, "/api/v1/online/authorize", idempotencyKey, body, &response); err != nil {
		return nil, err
	}
	return c.installLease(ctx, response.LeaseToken, body.ProtocolVersion)
}

// RenewOnline 按当前签名租约的绑定方案与修订号请求续签。
func (c *client) RenewOnline(ctx context.Context) (*Status, error) {
	if err := requireContext(ctx); err != nil {
		return nil, err
	}
	c.requestLock.Lock()
	defer c.requestLock.Unlock()
	content, err := readBoundedFile(c.leasePath())
	if err != nil {
		return nil, fmt.Errorf("read cached lease: %w", err)
	}
	payload, _, err := c.keys.VerifyLease(content)
	if err != nil {
		return nil, err
	}
	server := c.currentServerURL()
	if server == "" {
		return nil, fmt.Errorf("authorization server URL is required for renewal")
	}
	machine, err := c.machineForBinding(ctx, payload.MachineBinding)
	if err != nil {
		return nil, err
	}
	if payload.MachineBinding != nil {
		if payload.AppID != c.config.AppID {
			return nil, license.NewValidationError(license.ErrAppMismatch, "appId", nil)
		}
		if payload.InstanceID != c.config.InstanceID {
			return nil, license.NewValidationError(license.ErrInstanceMismatch, "instanceId", nil)
		}
		if payload.MachineID != machine {
			return nil, license.NewValidationError(license.ErrMachineMismatch, "machineId", nil)
		}
	}
	metadata, err := newRequestMetadata(c.config.Clock)
	if err != nil {
		return nil, err
	}
	idempotencyKey, err := randomToken(24)
	if err != nil {
		return nil, err
	}
	body := struct {
		ProtocolVersion string                   `json:"protocolVersion"`
		AppID           string                   `json:"appId"`
		SDKVersion      string                   `json:"sdkVersion"`
		InstanceID      string                   `json:"instanceId"`
		MachineID       string                   `json:"machineId"`
		MachineBinding  *machineidentity.Binding `json:"machineBinding,omitempty"`
		LeaseID         string                   `json:"leaseId"`
		LeaseRevision   int64                    `json:"leaseRevision"`
		LeaseToken      string                   `json:"leaseToken"`
		RequestID       string                   `json:"requestId"`
		Timestamp       time.Time                `json:"timestamp"`
		Nonce           string                   `json:"nonce"`
	}{
		payload.SchemaVersion, c.config.AppID, Version, payload.InstanceID, machine, payload.MachineBinding,
		payload.LeaseID, payload.Revision, base64.RawURLEncoding.EncodeToString(content),
		metadata.requestID, metadata.timestamp, metadata.nonce,
	}
	var response leaseResponse
	if err := c.postJSON(ctx, server, "/api/v1/online/renew", idempotencyKey, body, &response); err != nil {
		status, localErr := c.verifyCachedLease(ctx)
		if localErr == nil {
			return status, err
		}
		return nil, err
	}
	return c.installLease(ctx, response.LeaseToken, payload.SchemaVersion)
}

func (c *client) installLease(ctx context.Context, encoded, expectedVersion string) (*Status, error) {
	content, err := decodeEnvelope(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode signed lease: %w", err)
	}
	payload, _, err := c.keys.VerifyLease(content)
	if err != nil {
		return nil, err
	}
	if payload.SchemaVersion != expectedVersion {
		return nil, license.NewValidationError(license.ErrUnsupportedFormat, "schemaVersion", nil)
	}
	now := c.config.Clock().UTC()
	status, err := c.verifyLeaseContent(ctx, content, now)
	if err != nil {
		return statusPointer(status), err
	}
	if err := atomicWriteValidated(c.leasePath(), content, 0o600, func(staged []byte) error {
		_, verifyErr := c.verifyLeaseContent(ctx, staged, now)
		return verifyErr
	}); err != nil {
		return nil, err
	}
	c.setStatus(status)
	return statusPointer(status), nil
}

func (c *client) verifyCachedLease(ctx context.Context) (*Status, error) {
	content, err := readBoundedFile(c.leasePath())
	if err != nil {
		return nil, err
	}
	status, err := c.verifyLeaseContent(ctx, content, c.config.Clock().UTC())
	c.setStatus(status)
	return statusPointer(status), err
}

// VerifyOnlineLease 离线检查最近缓存的签名租约，按签名时间窗判断当前租约状态。
func (c *client) VerifyOnlineLease(ctx context.Context) (*Status, error) {
	if err := requireContext(ctx); err != nil {
		return nil, err
	}
	return c.verifyCachedLease(ctx)
}

func (c *client) verifyLeaseContent(ctx context.Context, content []byte, now time.Time) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	payload, _, err := c.keys.VerifyLease(content)
	if err != nil {
		return Status{LeaseState: string(license.LeaseDenied), Reason: string(license.CodeOf(err)), VerifiedAt: now}, err
	}
	machine, err := c.machineForBinding(ctx, payload.MachineBinding)
	if err != nil {
		if payload.MachineBinding != nil {
			return Status{LeaseState: string(license.LeaseDenied), Reason: string(license.CodeOf(err)), VerifiedAt: now}, err
		}
		return Status{}, err
	}
	internalStatus, err := license.ValidateLease(payload, license.VerifyOptions{
		AppID:      c.config.AppID,
		AppVersion: c.config.AppVersion,
		MachineID:  machine,
		InstanceID: c.config.InstanceID,
		Now:        now,
	})
	return exportStatus(internalStatus), err
}

func (c *client) prepareOnline(override, instanceID, idempotencyKey string) (string, string, string, error) {
	server := strings.TrimRight(override, "/")
	if server == "" {
		server = c.currentServerURL()
	}
	if server == "" {
		return "", "", "", fmt.Errorf("authorization server URL is required")
	}
	if _, err := validateServerURL(server); err != nil {
		return "", "", "", err
	}
	if instanceID == "" {
		instanceID = c.config.InstanceID
	}
	if instanceID == "" || len(instanceID) > 100 {
		return "", "", "", fmt.Errorf("invalid instanceId")
	}
	if idempotencyKey == "" {
		var err error
		idempotencyKey, err = randomToken(24)
		if err != nil {
			return "", "", "", err
		}
	}
	if len(idempotencyKey) < 16 || len(idempotencyKey) > 128 {
		return "", "", "", fmt.Errorf("idempotency key must contain 16 to 128 characters")
	}
	c.mu.Lock()
	c.serverURL = server
	c.mu.Unlock()
	return server, instanceID, idempotencyKey, nil
}

func (c *client) currentServerURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serverURL
}

func (c *client) leasePath() string { return c.config.LicensePath + ".lease" }

func (c *client) postJSON(ctx context.Context, server, endpoint, idempotencyKey string, body, output any) error {
	base, err := validateServerURL(server)
	if err != nil {
		return err
	}
	base.Path = strings.TrimRight(base.Path, "/") + endpoint
	base.RawPath = ""
	requestBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal AppHub request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("create AppHub request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response, err := c.config.HTTPClient.Do(request)
	if err != nil {
		return fmt.Errorf("call AppHub authorization service: %w", err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, maxLocalArtifactSize+1))
	if err != nil {
		return fmt.Errorf("read AppHub response: %w", err)
	}
	if len(content) > maxLocalArtifactSize {
		return fmt.Errorf("AppHub response exceeds size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure apiResponse[apiErrorData]
		_ = json.Unmarshal(content, &failure)
		return &APIError{HTTPStatus: response.StatusCode, Code: failure.Code, Reason: failure.Data.Reason, Message: failure.Message, TraceID: failure.TraceID}
	}
	var success apiResponse[json.RawMessage]
	if err := json.Unmarshal(content, &success); err != nil {
		return fmt.Errorf("decode AppHub response: %w", err)
	}
	if success.Code != 0 {
		return &APIError{HTTPStatus: response.StatusCode, Code: success.Code, Message: success.Message, TraceID: success.TraceID}
	}
	if err := json.Unmarshal(success.Data, output); err != nil {
		return fmt.Errorf("decode AppHub response data: %w", err)
	}
	return nil
}

type requestMetadata struct {
	requestID string
	timestamp time.Time
	nonce     string
}

// newRequestMetadata 为在线请求生成请求标识、随机数和 UTC 时间戳。
func newRequestMetadata(clock func() time.Time) (requestMetadata, error) {
	requestID, err := randomToken(18)
	if err != nil {
		return requestMetadata{}, err
	}
	nonce, err := randomToken(16)
	if err != nil {
		return requestMetadata{}, err
	}
	return requestMetadata{requestID: requestID, timestamp: clock().UTC(), nonce: nonce}, nil
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate secure request token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func decodeEnvelope(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "{") {
		return []byte(value), nil
	}
	content, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url envelope")
	}
	if len(content) == 0 || len(content) > maxLocalArtifactSize {
		return nil, fmt.Errorf("invalid envelope size")
	}
	return content, nil
}
