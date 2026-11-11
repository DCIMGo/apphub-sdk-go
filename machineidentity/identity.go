// Package machineidentity 采集 AppHub 统一机器身份并生成授权申请。
package machineidentity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"
)

// Scheme 标识计算机器摘要的规则版本。
const Scheme = "dcimgo-machine-v1"

// RequestVersion 标识统一授权申请的 JSON 版本。
const RequestVersion = "2.0"

// RequestCodePrefix 标识可粘贴的一行申请码格式。
const RequestCodePrefix = "AHM1."
const maxRequestCodeLength = 4096

// Binding 描述授权绑定的身份方案、范围、平台和标识来源。
type Binding struct {
	Scheme   string `json:"scheme"`
	Scope    string `json:"scope"`
	Platform string `json:"platform"`
	Provider string `json:"provider"`
}

// Valid 判断平台和标识来源是否为当前支持的配对。
func (b Binding) Valid() bool {
	return b.Scheme == Scheme && b.Scope == "os-installation" &&
		(b.Platform == "windows" && b.Provider == "windows.machine-guid" ||
			b.Platform == "linux" && b.Provider == "linux.machine-id")
}

// Identity 保存派生后的机器摘要和绑定描述。
type Identity struct {
	MachineID string
	Binding   Binding
}

// Collect 读取当前系统已有的安装标识并计算机器摘要。
func Collect(ctx context.Context) (Identity, error) {
	if ctx == nil {
		return Identity{}, errors.New("machine identity requires a context")
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	raw, binding, err := readInstallationID()
	if err != nil {
		return Identity{}, err
	}
	return derive(raw, binding)
}

var machineCode = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$`)

// derive 规范化标识，再按协议域、平台和来源计算 HMAC-SHA256 摘要。
func derive(raw string, binding Binding) (Identity, error) {
	if !binding.Valid() {
		return Identity{}, errors.New("unsupported machine identity provider")
	}
	normalized := strings.Trim(raw, "\t\n\v\f\r ")
	if binding.Platform == "windows" {
		if strings.HasPrefix(normalized, "{") && strings.HasSuffix(normalized, "}") {
			normalized = normalized[1 : len(normalized)-1]
		}
		if uuid.MatchString(normalized) {
			normalized = strings.ReplaceAll(normalized, "-", "")
		}
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil || len(decoded) != 16 || normalized == strings.Repeat("0", 32) {
		return Identity{}, errors.New("system installation identity is invalid or not initialized")
	}
	h := hmac.New(sha256.New, []byte("dcimgo/apphub/device-binding/v1"))
	_, _ = h.Write([]byte(strings.Join([]string{binding.Scope, binding.Platform, binding.Provider, strings.ToLower(normalized)}, "\x00")))
	return Identity{MachineID: "sha256:" + hex.EncodeToString(h.Sum(nil)), Binding: binding}, nil
}

type authorizationRequest struct {
	SchemaVersion string    `json:"schemaVersion"`
	AppID         string    `json:"appId"`
	AppVersion    string    `json:"appVersion"`
	InstanceID    string    `json:"instanceId"`
	MachineID     string    `json:"machineId"`
	Binding       Binding   `json:"machineBinding"`
	GeneratedAt   time.Time `json:"generatedAt"`
}

func (i Identity) request(appID, appVersion, instanceID string, at time.Time) (authorizationRequest, error) {
	if strings.TrimSpace(appID) == "" || strings.TrimSpace(appVersion) == "" ||
		instanceID == "" || instanceID != strings.TrimSpace(instanceID) || len(instanceID) > 100 ||
		strings.IndexFunc(instanceID, unicode.IsControl) >= 0 || at.IsZero() || !i.Binding.Valid() || !machineCode.MatchString(i.MachineID) {
		return authorizationRequest{}, errors.New("invalid machine authorization request")
	}
	return authorizationRequest{RequestVersion, appID, appVersion, instanceID, i.MachineID, i.Binding, at.UTC()}, nil
}

// MarshalRequest 生成 AppHub 可读取的授权申请 JSON。
func (i Identity) MarshalRequest(appID, appVersion, instanceID string, at time.Time) ([]byte, error) {
	request, err := i.request(appID, appVersion, instanceID, at)
	if err != nil {
		return nil, err
	}
	return json.Marshal(request)
}

// MarshalRequestCode 生成可粘贴的一行 AHM1 申请码。
// 运行架构用于展示，机器绑定由 MachineID 确定。
func (i Identity) MarshalRequestCode(appID, appVersion, instanceID string, at time.Time) (string, error) {
	request, err := i.request(appID, appVersion, instanceID, at)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(struct {
		authorizationRequest
		Architecture string `json:"architecture"`
	}{request, runtime.GOARCH})
	if err != nil {
		return "", err
	}
	if len(RequestCodePrefix)+base64.RawURLEncoding.EncodedLen(len(payload)) > maxRequestCodeLength {
		return "", errors.New("machine authorization request code exceeds the length limit")
	}
	return RequestCodePrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}
