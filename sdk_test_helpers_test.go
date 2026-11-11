package apphubsdk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	license "github.com/DCIMGo/apphub-sdk-go/internal/protocol"
	licensefile "github.com/DCIMGo/apphub-sdk-go/internal/protocol"
)

type sdkTestFixture struct {
	publicKey ed25519.PublicKey
	sign      licensefile.SignFunc
	now       time.Time
	machineID string
}

func newSDKTestFixture(t *testing.T) sdkTestFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign, err := licensefile.Ed25519SignFunc(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	machineID, err := license.NormalizeMachineComponents("host=node-1")
	if err != nil {
		t.Fatal(err)
	}
	return sdkTestFixture{
		publicKey: publicKey,
		sign:      sign,
		now:       time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		machineID: machineID,
	}
}

func (fixture sdkTestFixture) config(t *testing.T, clock func() time.Time) Config {
	t.Helper()
	if clock == nil {
		clock = func() time.Time { return fixture.now }
	}
	return Config{
		AppID:         "go-dcim",
		AppVersion:    "2.1.0",
		InstanceID:    "primary",
		LicensePath:   filepath.Join(t.TempDir(), "app.license"),
		PublicKeys:    map[string]ed25519.PublicKey{"key-1": fixture.publicKey},
		MachineSource: fixedMachineSource{"host=node-1"},
		Clock:         clock,
	}
}

func (fixture sdkTestFixture) licensePayload() license.Payload {
	expiresAt := fixture.now.Add(48 * time.Hour)
	return license.Payload{
		SchemaVersion:     license.SchemaVersionV1,
		LicenseID:         "lic_1",
		LicenseItemID:     "li_1",
		LicenseRevision:   1,
		AppID:             "go-dcim",
		InstanceID:        "primary",
		MachineID:         fixture.machineID,
		AuthorizationMode: license.ModeOffline,
		IssuedAt:          fixture.now.Add(-time.Hour),
		NotBefore:         fixture.now.Add(-time.Hour),
		ExpiresAt:         &expiresAt,
		VersionRange:      license.VersionRange{Minimum: "2.0.0", MaximumExclusive: "3.0.0"},
		Entitlements: license.Entitlements{
			Features: map[string]bool{"asset.export": true},
			Limits:   map[string]int64{"asset.max": 10},
			Configs:  map[string]json.RawMessage{"theme": json.RawMessage(`"dark"`)},
		},
	}
}

func (fixture sdkTestFixture) signLicense(t *testing.T, payload license.Payload) []byte {
	t.Helper()
	content, err := licensefile.SignLicense(context.Background(), payload, "key-1", fixture.sign)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func (fixture sdkTestFixture) leasePayload() license.LeasePayload {
	return license.LeasePayload{
		SchemaVersion:   license.SchemaVersionV1,
		AuthorizationID: "auth_1",
		LeaseID:         "lease_1",
		Revision:        1,
		LicenseItemID:   "li_1",
		LicenseRevision: 1,
		AppID:           "go-dcim",
		InstanceID:      "primary",
		MachineID:       fixture.machineID,
		Status:          license.LeaseAuthorized,
		IssuedAt:        fixture.now.Add(-time.Hour),
		RenewAfter:      fixture.now.Add(time.Hour),
		ExpiresAt:       fixture.now.Add(2 * time.Hour),
		GraceUntil:      fixture.now.Add(3 * time.Hour),
		GraceEndPolicy:  license.GraceReadOnly,
		VersionRange:    license.VersionRange{Minimum: "2.0.0", MaximumExclusive: "3.0.0"},
		Entitlements: license.Entitlements{
			Features: map[string]bool{"asset.export": true},
			Limits:   map[string]int64{"asset.max": 10},
		},
	}
}

func (fixture sdkTestFixture) signLease(t *testing.T, payload license.LeasePayload) []byte {
	t.Helper()
	content, err := licensefile.SignLease(context.Background(), payload, "key-1", fixture.sign)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func encodedLease(content []byte) string {
	return base64.RawURLEncoding.EncodeToString(content)
}
