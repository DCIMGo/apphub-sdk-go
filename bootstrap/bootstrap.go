// Package bootstrap contains the small, shared startup adapter used by the
// first-party applications. It keeps public-key file parsing and startup
// policy identical across go-dcim, go-monitor, go-north, go-push and
// go-sample.
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	apphubsdk "github.com/DCIMGo/apphub-sdk-go"
)

type Config struct {
	AppID                     string
	AppVersion                string
	InstanceID                string
	ServerURL                 string
	LicensePath               string
	PublicKeyPath             string
	UseUnifiedMachineIdentity bool
}

// FileConfig is the portable local-development configuration format shared by
// first-party applications. Environment variables with the APPHUB_SDK_ prefix
// override non-empty file values, so the same file can be used locally while a
// deployment injects only the values that differ.
type FileConfig struct {
	AppID                     string `json:"appId"`
	AppVersion                string `json:"appVersion"`
	InstanceID                string `json:"instanceId"`
	ServerURL                 string `json:"serverUrl"`
	LicensePath               string `json:"licensePath"`
	PublicKeyPath             string `json:"publicKeyPath"`
	UseUnifiedMachineIdentity bool   `json:"useUnifiedMachineIdentity,omitempty"`
}

// LoadConfig reads a JSON configuration file and applies APPHUB_SDK_*
// overrides. An empty path resolves to ./config/apphub-sdk.json. The loader is
// intentionally small and dependency-free so applications can use it before
// their main framework is initialized.
func LoadConfig(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		path = filepath.Join("config", "apphub-sdk.json")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read SDK config %q: %w", path, err)
	}
	var file FileConfig
	if err := json.Unmarshal(content, &file); err != nil {
		return Config{}, fmt.Errorf("decode SDK config %q: %w", path, err)
	}
	value := func(fileValue, envName string) string {
		if envValue := strings.TrimSpace(os.Getenv(envName)); envValue != "" {
			return envValue
		}
		return strings.TrimSpace(fileValue)
	}
	return Config{
		UseUnifiedMachineIdentity: file.UseUnifiedMachineIdentity,
		AppID:                     value(file.AppID, "APPHUB_SDK_APP_ID"), AppVersion: value(file.AppVersion, "APPHUB_SDK_APP_VERSION"),
		InstanceID: value(file.InstanceID, "APPHUB_SDK_INSTANCE_ID"), ServerURL: value(file.ServerURL, "APPHUB_SDK_SERVER_URL"),
		LicensePath: value(file.LicensePath, "APPHUB_SDK_LICENSE_PATH"), PublicKeyPath: value(file.PublicKeyPath, "APPHUB_SDK_PUBLIC_KEY_PATH"),
	}, nil
}

// NewFromConfig constructs a client from the local JSON configuration file.
func NewFromConfig(path string) (apphubsdk.Client, error) {
	config, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}
	return New(config)
}

type keyFile struct {
	Keys []keyEntry `json:"keys"`
}

type keyEntry struct {
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKeyBase64"`
}

// LoadPublicKeys reads the public verification-key envelope distributed with
// an application release. Private keys and activation codes are never accepted
// by this parser.
func LoadPublicKeys(path string) (map[string]ed25519.PublicKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}
	var envelope keyFile
	if err := json.Unmarshal(content, &envelope); err != nil {
		return nil, fmt.Errorf("decode public key file: %w", err)
	}
	if len(envelope.Keys) == 0 {
		return nil, fmt.Errorf("public key file contains no keys")
	}
	keys := make(map[string]ed25519.PublicKey, len(envelope.Keys))
	for _, entry := range envelope.Keys {
		if strings.TrimSpace(entry.KeyID) == "" {
			return nil, fmt.Errorf("public key id is required")
		}
		if _, exists := keys[entry.KeyID]; exists {
			return nil, fmt.Errorf("public key id %q is duplicated", entry.KeyID)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(entry.PublicKey))
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("public key %q is not a base64 Ed25519 key", entry.KeyID)
		}
		keys[entry.KeyID] = ed25519.PublicKey(decoded)
	}
	return keys, nil
}

// New creates a client using the shared first-party configuration contract.
func New(config Config) (apphubsdk.Client, error) {
	keys, err := LoadPublicKeys(config.PublicKeyPath)
	if err != nil {
		return nil, err
	}
	return apphubsdk.New(apphubsdk.Config{
		AppID: config.AppID, AppVersion: config.AppVersion, InstanceID: config.InstanceID,
		UseUnifiedMachineIdentity: config.UseUnifiedMachineIdentity,
		ServerURL:                 config.ServerURL, LicensePath: config.LicensePath, PublicKeys: keys,
	})
}

// VerifyStartup enforces the common startup gate. Offline and activate-once
// applications require a usable local file; online applications may continue
// with a valid lease or its configured grace state.
func VerifyStartup(ctx context.Context, client apphubsdk.Client) (*apphubsdk.Status, error) {
	localStatus, localErr := client.VerifyLocal(ctx)
	if localErr == nil && (localStatus.LocalState == "active" || localStatus.LocalState == "expiring") {
		return localStatus, nil
	}
	leaseStatus, leaseErr := client.VerifyOnlineLease(ctx)
	if leaseErr == nil && (leaseStatus.LeaseState == "authorized" || leaseStatus.LeaseState == "renewing" || leaseStatus.LeaseState == "grace") {
		return leaseStatus, nil
	}
	if localErr != nil && leaseErr != nil {
		return localStatus, fmt.Errorf("local license unavailable (%v) and cached online lease unavailable (%v)", localErr, leaseErr)
	}
	return localStatus, fmt.Errorf("authorization is not usable: local=%s lease=%s", localStatus.LocalState, leaseStatus.LeaseState)
}
