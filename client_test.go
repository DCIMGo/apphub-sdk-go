package apphubsdk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	license "github.com/DCIMGo/apphub-sdk-go/internal/protocol"
	licensefile "github.com/DCIMGo/apphub-sdk-go/internal/protocol"
)

type fixedMachineSource []string

func (source fixedMachineSource) Components(context.Context) ([]string, error) {
	return append([]string(nil), source...), nil
}

func TestImportVerifyAndClockRollback(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	sign, _ := licensefile.Ed25519SignFunc(privateKey)
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	machine, _ := license.NormalizeMachineComponents("host=node-1")
	expires := now.Add(24 * time.Hour)
	payload := license.Payload{
		SchemaVersion: license.SchemaVersionV1, LicenseID: "lic_1", LicenseItemID: "li_1", LicenseRevision: 1,
		AppID: "go-dcim", InstanceID: "primary", MachineID: machine, AuthorizationMode: license.ModeOffline,
		IssuedAt: now.Add(-time.Hour), NotBefore: now.Add(-time.Hour), ExpiresAt: &expires,
		VersionRange: license.VersionRange{Minimum: "2.0.0", MaximumExclusive: "3.0.0"},
		Entitlements: license.Entitlements{Features: map[string]bool{"asset.export": true}, Limits: map[string]int64{"asset.max": 10}, Configs: map[string]json.RawMessage{"theme": json.RawMessage(`"dark"`)}},
	}
	content, err := licensefile.SignLicense(context.Background(), payload, "license-key-1", sign)
	if err != nil {
		t.Fatal(err)
	}
	licensePath := filepath.Join(t.TempDir(), "app.license")
	currentTime := now
	sdk, err := New(Config{
		AppID: "go-dcim", AppVersion: "2.1.0", InstanceID: "primary", LicensePath: licensePath,
		PublicKeys: map[string]ed25519.PublicKey{"license-key-1": publicKey}, MachineSource: fixedMachineSource{"host=node-1"},
		Clock: func() time.Time { return currentTime }, ClockRollbackSkew: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := sdk.ImportLicense(context.Background(), content)
	if err != nil || (status.LocalState != "active" && status.LocalState != "expiring") || !sdk.HasFeature("asset.export") {
		t.Fatalf("import failed: %#v %v", status, err)
	}
	if limit, ok := sdk.GetIntLimit("asset.max"); !ok || limit != 10 {
		t.Fatalf("limit not available: %d %v", limit, ok)
	}
	config, ok := sdk.GetConfig("theme")
	if !ok || config != "dark" {
		t.Fatalf("config not available: %#v %v", config, ok)
	}
	currentTime = now.Add(-10 * time.Minute)
	status, err = sdk.VerifyLocal(context.Background())
	if err == nil || status.LocalState != "clock_rollback_suspected" {
		t.Fatalf("clock rollback not detected: %#v %v", status, err)
	}
}

func TestInvalidImportPreservesExistingLicense(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	sign, _ := licensefile.Ed25519SignFunc(privateKey)
	now := time.Now().UTC()
	machine, _ := license.NormalizeMachineComponents("host=node-1")
	payload := license.Payload{
		SchemaVersion: license.SchemaVersionV1, LicenseID: "lic_1", LicenseItemID: "li_1", LicenseRevision: 1,
		AppID: "go-dcim", InstanceID: "primary", MachineID: machine, AuthorizationMode: license.ModeOffline,
		IssuedAt: now.Add(-time.Hour), NotBefore: now.Add(-time.Hour),
	}
	content, _ := licensefile.SignLicense(context.Background(), payload, "key-1", sign)
	path := filepath.Join(t.TempDir(), "app.license")
	sdk, _ := New(Config{AppID: "go-dcim", AppVersion: "2.1.0", InstanceID: "primary", LicensePath: path, PublicKeys: map[string]ed25519.PublicKey{"key-1": publicKey}, MachineSource: fixedMachineSource{"host=node-1"}, Clock: func() time.Time { return now }})
	if _, err := sdk.ImportLicense(context.Background(), content); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), content...)
	tampered[len(tampered)/2] ^= 1
	if _, err := sdk.ImportLicense(context.Background(), tampered); err == nil {
		t.Fatal("tampered license imported")
	}
	if state := sdk.Status().LocalState; state != "active" && state != "expiring" {
		t.Fatal("invalid import changed the last verified status")
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(content) {
		t.Fatal("invalid import replaced the valid local license")
	}
}

func TestActivateOnceDownloadsAndInstallsVerifiedLicense(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	sign, _ := licensefile.Ed25519SignFunc(privateKey)
	now := time.Now().UTC()
	machine, _ := license.NormalizeMachineComponents("host=node-1")
	payload := license.Payload{
		SchemaVersion: license.SchemaVersionV1, LicenseID: "lic_1", LicenseItemID: "li_1", LicenseRevision: 2,
		AppID: "go-dcim", InstanceID: "primary", MachineID: machine, AuthorizationMode: license.ModeActivateOnce,
		IssuedAt: now, NotBefore: now.Add(-time.Minute),
	}
	content, _ := licensefile.SignLicense(context.Background(), payload, "key-1", sign)
	digest := sha256.Sum256(content)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/activation/issue" || request.Header.Get("Idempotency-Key") == "" {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"code": 0, "message": "success", "traceId": "trace-1",
			"data": map[string]any{
				"activationId": "act_1", "licenseId": "lic_1", "licenseItemId": "li_1", "licenseRevision": 2,
				"file": map[string]any{"name": "go-dcim.license", "content": base64.RawURLEncoding.EncodeToString(content), "size": len(content), "sha256": hex.EncodeToString(digest[:])},
			},
		})
	}))
	defer server.Close()
	sdk, err := New(Config{
		AppID: "go-dcim", AppVersion: "2.1.0", InstanceID: "primary", ServerURL: server.URL,
		LicensePath: filepath.Join(t.TempDir(), "app.license"), PublicKeys: map[string]ed25519.PublicKey{"key-1": publicKey},
		MachineSource: fixedMachineSource{"host=node-1"}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := sdk.ActivateOnce(context.Background(), ActivateRequest{ActivationCode: "ABCD-EFGH-IJKL", IdempotencyKey: "activation-request-0001"})
	if err != nil || status.LocalState != "active" || status.Mode != "activate_once" {
		t.Fatalf("online activation failed: %#v %v", status, err)
	}
}

func TestStatusIsImmutableSnapshot(t *testing.T) {
	status := Status{Features: map[string]bool{"x": true}}
	c := &client{status: status}
	copy := c.Status()
	copy.Features["x"] = false
	if !c.Status().Features["x"] {
		t.Fatal("caller mutated internal status")
	}
}

func TestAuthorizationRedirectCannotChangeOrigin(t *testing.T) {
	original, _ := http.NewRequest(http.MethodPost, "https://apphub.example.com/api/v1/activation/issue", nil)
	redirect, _ := http.NewRequest(http.MethodPost, "https://attacker.example/api/v1/activation/issue", nil)
	if err := secureRedirect(redirect, []*http.Request{original}); err == nil {
		t.Fatal("cross-origin redirect accepted")
	}
}
