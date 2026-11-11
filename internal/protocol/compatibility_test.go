package protocol

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

// This fixture locks the server/SDK envelope domain, canonical JSON payload,
// and RawURL signature encoding. A protocol change must introduce a new
// schema/purpose instead of silently changing these bytes.
func TestLicenseEnvelopeCompatibilityFixture(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	sign, err := Ed25519SignFunc(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := Payload{
		SchemaVersion: SchemaVersionV1, LicenseID: "lic_fixture", LicenseItemID: "item_fixture", LicenseRevision: 1,
		AppID: "go-sample", InstanceID: "primary", MachineID: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		AuthorizationMode: ModeOffline, IssuedAt: time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC), NotBefore: time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC),
		VersionRange: VersionRange{Minimum: "1.0.0", MaximumExclusive: "2.0.0"}, Entitlements: Entitlements{Features: map[string]bool{"fixture": true}},
	}
	content, err := SignLicense(context.Background(), payload, "license-fixture-1", sign)
	if err != nil {
		t.Fatal(err)
	}
	const expectedBase64 = "eyJzY2hlbWFWZXJzaW9uIjoiMS4wIiwicHVycG9zZSI6ImxpY2Vuc2UiLCJrZXlJZCI6ImxpY2Vuc2UtZml4dHVyZS0xIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsInBheWxvYWQiOnsic2NoZW1hVmVyc2lvbiI6IjEuMCIsImxpY2Vuc2VJZCI6ImxpY19maXh0dXJlIiwibGljZW5zZUl0ZW1JZCI6Iml0ZW1fZml4dHVyZSIsImxpY2Vuc2VSZXZpc2lvbiI6MSwiYXBwSWQiOiJnby1zYW1wbGUiLCJpbnN0YW5jZUlkIjoicHJpbWFyeSIsIm1hY2hpbmVJZCI6InNoYTI1NjowMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmIiwiYXV0aG9yaXphdGlvbk1vZGUiOiJvZmZsaW5lIiwiaXNzdWVkQXQiOiIyMDI2LTA4LTEyVDAwOjAwOjAwWiIsIm5vdEJlZm9yZSI6IjIwMjYtMDgtMTJUMDA6MDA6MDBaIiwidmVyc2lvblJhbmdlIjp7Im1pbmltdW0iOiIxLjAuMCIsIm1heGltdW1FeGNsdXNpdmUiOiIyLjAuMCJ9LCJlbnRpdGxlbWVudHMiOnsiZmVhdHVyZXMiOnsiZml4dHVyZSI6dHJ1ZX19LCJ1cGRhdGVQb2xpY3kiOnsiZW5hYmxlZCI6ZmFsc2UsImFsbG93Um9sbGJhY2siOmZhbHNlfX0sInNpZ25hdHVyZSI6ImdlcXNqSjJaN2ZCNjVGWWhJNTY3S2dHVlN3MHNaXzBxal9fRnJQOFVwZThNbmtkYVRNa1NVeXR5ZTZ2TmlsOFk5bUlpRFFJTWtZX0J5a1ZVRkRFREJnIn0"
	encoded := base64.RawStdEncoding.EncodeToString(content)
	if encoded != expectedBase64 {
		t.Fatalf("protocol fixture changed:\n%s", encoded)
	}
	keys := KeySet{"license-fixture-1": privateKey.Public().(ed25519.PublicKey)}
	verified, _, err := keys.VerifyLicense(content)
	if err != nil || verified.LicenseID != payload.LicenseID {
		t.Fatalf("fixture verify=%#v err=%v", verified, err)
	}
}
