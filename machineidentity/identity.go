// Package machineidentity collects the versioned AppHub machine identity.
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

const Scheme = "dcimgo-machine-v1"
const RequestVersion = "2.0"

// RequestCodePrefix identifies the one-line request format.
const RequestCodePrefix = "AHM1."
const maxRequestCodeLength = 4096

// Binding identifies the inputs and scope of a signed machine ID.
type Binding struct {
	Scheme   string `json:"scheme"`
	Scope    string `json:"scope"`
	Platform string `json:"platform"`
	Provider string `json:"provider"`
}

func (b Binding) Valid() bool {
	return b.Scheme == Scheme && b.Scope == "os-installation" &&
		(b.Platform == "windows" && b.Provider == "windows.machine-guid" ||
			b.Platform == "linux" && b.Provider == "linux.machine-id")
}

// Identity contains only the derived code and the public binding description.
type Identity struct {
	MachineID string
	Binding   Binding
}

// Collect reads the local system installation identity without creating one.
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

// MarshalRequest creates the portable JSON request consumed by AppHub.
func (i Identity) MarshalRequest(appID, appVersion, instanceID string, at time.Time) ([]byte, error) {
	request, err := i.request(appID, appVersion, instanceID, at)
	if err != nil {
		return nil, err
	}
	return json.Marshal(request)
}

// MarshalRequestCode creates a one-line code for pasting into AppHub. The
// collector architecture is descriptive and does not affect machine binding.
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
