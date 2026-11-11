package apphubsdk

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	license "github.com/DCIMGo/apphub-sdk-go/internal/protocol"
	licensefile "github.com/DCIMGo/apphub-sdk-go/internal/protocol"
)

type failingMachineSource struct{}

func (failingMachineSource) Components(context.Context) ([]string, error) {
	return nil, errors.New("machine source unavailable")
}

func TestNewValidatesConfiguration(t *testing.T) {
	fixture := newSDKTestFixture(t)
	base := fixture.config(t, nil)

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing app", func(config *Config) { config.AppID = "" }},
		{"invalid app", func(config *Config) { config.AppID = "Go_DCIM" }},
		{"invalid version", func(config *Config) { config.AppVersion = "not-semver" }},
		{"missing path", func(config *Config) { config.LicensePath = "" }},
		{"missing keys", func(config *Config) { config.PublicKeys = nil }},
		{"invalid key", func(config *Config) { config.PublicKeys = map[string]ed25519.PublicKey{"bad": {1}} }},
		{"long instance", func(config *Config) { config.InstanceID = strings.Repeat("x", 101) }},
		{"insecure server", func(config *Config) { config.ServerURL = "http://example.com" }},
		{"server userinfo", func(config *Config) { config.ServerURL = "https://user@example.com" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			if _, err := New(config); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestMachineRequestUsesNormalizedIdentityAndDefaults(t *testing.T) {
	fixture := newSDKTestFixture(t)
	config := fixture.config(t, nil)
	config.InstanceID = ""
	config.MachineSource = nil
	sdk, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	content, err := sdk.MachineRequest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request := string(content)
	if !strings.Contains(request, `"schemaVersion":"1.0"`) || !strings.Contains(request, `"appId":"go-dcim"`) || !strings.Contains(request, `"machineId":"sha256:`) {
		t.Fatalf("unexpected machine request: %s", request)
	}

	config = fixture.config(t, nil)
	config.MachineSource = failingMachineSource{}
	sdk, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.MachineRequest(context.Background()); err == nil || !strings.Contains(err.Error(), "machine identity") {
		t.Fatalf("expected wrapped machine error, got %v", err)
	}
}

func TestVerifyLocalLicenseBoundaryStates(t *testing.T) {
	fixture := newSDKTestFixture(t)
	tests := []struct {
		name      string
		mutate    func(*license.Payload)
		wantState string
	}{
		{"not yet valid", func(payload *license.Payload) { payload.NotBefore = fixture.now.Add(time.Hour) }, "not_yet_valid"},
		{"expired", func(payload *license.Payload) { expired := fixture.now.Add(-time.Second); payload.ExpiresAt = &expired }, "expired"},
		{"app mismatch", func(payload *license.Payload) { payload.AppID = "go-monitor" }, "app_mismatch"},
		{"machine mismatch", func(payload *license.Payload) {
			payload.MachineID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, "machine_mismatch"},
		{"instance mismatch", func(payload *license.Payload) { payload.InstanceID = "other" }, "instance_mismatch"},
		{"version mismatch", func(payload *license.Payload) { payload.VersionRange.Minimum = "3.0.0" }, "version_mismatch"},
		{"unsupported format", func(payload *license.Payload) { payload.SchemaVersion = "99.0" }, "unsupported_format"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := fixture.licensePayload()
			test.mutate(&payload)
			config := fixture.config(t, nil)
			if err := os.WriteFile(config.LicensePath, fixture.signLicense(t, payload), 0o600); err != nil {
				t.Fatal(err)
			}
			sdk, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			status, err := sdk.VerifyLocal(context.Background())
			if err == nil || status.LocalState != test.wantState {
				t.Fatalf("want %s, got %#v, %v", test.wantState, status, err)
			}
			if sdk.HasFeature("asset.export") {
				t.Fatal("unusable authorization exposed a feature")
			}
		})
	}
}

func TestVerifyLocalMissingCorruptAndInvalidSignature(t *testing.T) {
	fixture := newSDKTestFixture(t)
	config := fixture.config(t, nil)
	sdk, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	status, err := sdk.VerifyLocal(context.Background())
	if err == nil || status.LocalState != "unlicensed" {
		t.Fatalf("missing license state: %#v %v", status, err)
	}

	if err := os.WriteFile(config.LicensePath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err = sdk.VerifyLocal(context.Background())
	if err == nil || status.LocalState != "file_corrupted" {
		t.Fatalf("corrupt license state: %#v %v", status, err)
	}

	content := fixture.signLicense(t, fixture.licensePayload())
	var envelope licensefile.Envelope
	if err := json.Unmarshal(content, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signature = strings.Repeat("A", 86)
	content, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.LicensePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	status, err = sdk.VerifyLocal(context.Background())
	if err == nil || status.LocalState != "invalid_signature" {
		t.Fatalf("signature state: %#v %v", status, err)
	}
}

func TestImportLicenseRejectsSizeAndMalformedClock(t *testing.T) {
	fixture := newSDKTestFixture(t)
	config := fixture.config(t, nil)
	sdk, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range [][]byte{nil, make([]byte, maxLocalArtifactSize+1)} {
		if _, err := sdk.ImportLicense(context.Background(), content); err == nil {
			t.Fatal("invalid license size accepted")
		}
	}
	if err := os.WriteFile(config.LicensePath+".clock", []byte("bad-clock"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.ImportLicense(context.Background(), fixture.signLicense(t, fixture.licensePayload())); err == nil || !strings.Contains(err.Error(), "parse verification clock") {
		t.Fatalf("malformed clock accepted: %v", err)
	}
}

func TestEntitlementAccessRequiresUsableStatusAndValidJSON(t *testing.T) {
	c := &client{status: Status{
		LocalState: "active",
		Features:   map[string]bool{"enabled": true},
		Limits:     map[string]int64{"max": 2},
		Configs:    map[string]json.RawMessage{"bad": json.RawMessage("{"), "ok": json.RawMessage(`{"x":1}`)},
	}}
	if value, ok := c.GetConfig("bad"); ok || value != nil {
		t.Fatal("invalid JSON config was exposed")
	}
	if _, ok := c.GetConfig("missing"); ok {
		t.Fatal("missing config was exposed")
	}
	c.setStatus(Status{LocalState: "expired", Features: map[string]bool{"enabled": true}, Limits: map[string]int64{"max": 2}})
	if c.HasFeature("enabled") {
		t.Fatal("expired feature was exposed")
	}
	if _, ok := c.GetIntLimit("max"); ok {
		t.Fatal("expired limit was exposed")
	}
}
