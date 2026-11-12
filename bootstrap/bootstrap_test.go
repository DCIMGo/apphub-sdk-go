package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	apphubsdk "github.com/DCIMGo/apphub-sdk-go"
)

type startupClient struct {
	local, lease       *apphubsdk.Status
	localErr, leaseErr error
}

func (c startupClient) VerifyLocal(context.Context) (*apphubsdk.Status, error) {
	return c.local, c.localErr
}
func (c startupClient) VerifyOnlineLease(context.Context) (*apphubsdk.Status, error) {
	return c.lease, c.leaseErr
}
func (startupClient) MachineID(context.Context) (string, error)      { return "", nil }
func (startupClient) MachineRequest(context.Context) ([]byte, error) { return nil, nil }
func (startupClient) ImportLicense(context.Context, []byte) (*apphubsdk.Status, error) {
	return nil, nil
}
func (startupClient) ActivateOnce(context.Context, apphubsdk.ActivateRequest) (*apphubsdk.Status, error) {
	return nil, nil
}
func (startupClient) AuthorizeOnline(context.Context, apphubsdk.AuthorizeRequest) (*apphubsdk.Status, error) {
	return nil, nil
}
func (startupClient) RenewOnline(context.Context) (*apphubsdk.Status, error) { return nil, nil }
func (startupClient) CheckUpdate(context.Context, apphubsdk.UpdateCheckRequest) (*apphubsdk.UpdateCheckResult, error) {
	return nil, nil
}
func (startupClient) StartAutoRenew(context.Context) error { return nil }
func (startupClient) StopAutoRenew()                       {}
func (startupClient) Status() apphubsdk.Status             { return apphubsdk.Status{} }
func (startupClient) HasFeature(string) bool               { return false }
func (startupClient) GetIntLimit(string) (int64, bool)     { return 0, false }
func (startupClient) GetConfig(string) (any, bool)         { return nil, false }

func TestLoadPublicKeysRejectsDuplicateAndMalformedEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(publicKey)
	content := `{"keys":[{"keyId":"license-1","publicKeyBase64":"` + encoded + `"},{"keyId":"license-1","publicKeyBase64":"` + encoded + `"}]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicKeys(path); err == nil {
		t.Fatal("duplicate key unexpectedly accepted")
	}
	if err := os.WriteFile(path, []byte(`{"keys":[{"keyId":"license-1","publicKeyBase64":"bad"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicKeys(path); err == nil {
		t.Fatal("malformed key unexpectedly accepted")
	}
}

func TestLoadConfigUsesFileValuesAndEnvironmentOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apphub-sdk.json")
	if err := os.WriteFile(path, []byte(`{"appId":"go-sample","appVersion":"1.0.0","instanceId":"file-instance","serverUrl":"http://127.0.0.1:60800","licensePath":"./data/sample.license","publicKeyPath":"./data/keys.json"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APPHUB_SDK_INSTANCE_ID", "env-instance")
	t.Setenv("APPHUB_SDK_SERVER_URL", "  ")
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.AppID != "go-sample" || config.InstanceID != "env-instance" ||
		config.ServerURL != "http://127.0.0.1:60800" || config.PublicKeyPath != "./data/keys.json" {
		t.Fatalf("unexpected SDK config: %#v", config)
	}
}

func TestLoadConfigRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apphub-sdk.json")
	if err := os.WriteFile(path, []byte(`{"appId":`), 0o600); err != nil {
		t.Fatal(err)
	}
	var syntaxError *json.SyntaxError
	if _, err := LoadConfig(path); !errors.As(err, &syntaxError) {
		t.Fatalf("LoadConfig error = %v, want wrapped JSON syntax error", err)
	}
}

func TestLoadConfigPreservesMissingFileError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	if _, err := LoadConfig(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadConfig error = %v, want wrapped missing-file error", err)
	}
}

func TestExampleConfigMatchesLocalBootstrapContract(t *testing.T) {
	config, err := LoadConfig(filepath.Join("..", "config", "apphub-sdk.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if config.AppID != "go-sample" || config.AppVersion == "" || config.InstanceID == "" {
		t.Fatalf("unexpected example SDK config: %#v", config)
	}
	if config.ServerURL != "http://127.0.0.1:50000" {
		t.Fatalf("example config must target local development server: %#v", config)
	}
}

func TestVerifyStartupFallsBackToCachedOnlineLease(t *testing.T) {
	lease := &apphubsdk.Status{LeaseState: "grace", GraceUntil: timePointer(time.Now().Add(time.Hour))}
	status, err := VerifyStartup(context.Background(), startupClient{local: &apphubsdk.Status{LocalState: "unlicensed"}, localErr: os.ErrNotExist, lease: lease})
	if err != nil || status.LeaseState != "grace" {
		t.Fatalf("status=%#v err=%v", status, err)
	}
}

func TestVerifyStartupFailsWhenBothArtifactsUnavailable(t *testing.T) {
	_, err := VerifyStartup(context.Background(), startupClient{local: &apphubsdk.Status{LocalState: "unlicensed"}, localErr: os.ErrNotExist, lease: &apphubsdk.Status{LeaseState: "unlicensed"}, leaseErr: os.ErrNotExist})
	if err == nil {
		t.Fatal("startup accepted missing license and lease")
	}
}

func timePointer(value time.Time) *time.Time { return &value }
