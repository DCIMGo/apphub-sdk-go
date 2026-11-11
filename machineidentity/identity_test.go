package machineidentity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCanonicalVectors(t *testing.T) {
	windows := Binding{Scheme, "os-installation", "windows", "windows.machine-guid"}
	linux := Binding{Scheme, "os-installation", "linux", "linux.machine-id"}
	for _, test := range []struct {
		binding Binding
		raw     string
		want    string
	}{
		{windows, " \t{00112233-4455-6677-8899-AABBCCDDEEFF}\r\n", "bc193aab419298862e59952d0976c38da9147cd0995a1edbdee4f9a0e42abb71"},
		{linux, "00112233445566778899AABBCCDDEEFF\n", "84d7beba0871179ad219175677bcf397fae1a5da90d19a3644afa9782e4c8a3d"},
	} {
		id, err := derive(test.raw, test.binding)
		if err != nil || id.MachineID != "sha256:"+test.want {
			t.Fatalf("%s canonical vector mismatch: %v", test.binding.Platform, err)
		}
	}
	for _, raw := range []string{"", "uninitialized", strings.Repeat("0", 32), "00112233-4455-6677-8899-aabbccddeeff", "\u00a000112233445566778899aabbccddeeff"} {
		if _, err := derive(raw, linux); err == nil {
			t.Fatal("invalid Linux installation identity accepted")
		}
	}
	if _, err := derive("00112233445566778899aabbccddeeff", Binding{Scheme, "os-installation", "linux", "windows.machine-guid"}); err == nil {
		t.Fatal("mismatched binding accepted")
	}
}

func TestNativeCollectionAndPortableRequests(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skip("phase one supports Windows and Linux")
	}
	first, err := Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Collect(context.Background())
	if err != nil || first != second || first.Binding.Platform != runtime.GOOS {
		t.Fatalf("native identity is not stable: %v", err)
	}
	for _, app := range []string{"application-one", "application-two"} {
		content, err := first.MarshalRequest(app, "1.2.3", "default", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var request struct {
			AppID         string  `json:"appId"`
			SchemaVersion string  `json:"schemaVersion"`
			MachineID     string  `json:"machineId"`
			Binding       Binding `json:"machineBinding"`
		}
		if json.Unmarshal(content, &request) != nil || request.AppID != app || request.SchemaVersion != RequestVersion ||
			request.MachineID != first.MachineID || request.Binding != first.Binding {
			t.Fatal("portable request did not keep the native machine binding")
		}
	}
}

func TestRequestCodeKeepsOriginalBindingAndRequestFields(t *testing.T) {
	identity, err := derive("00112233445566778899aabbccddeeff", Binding{Scheme, "os-installation", "linux", "linux.machine-id"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 11, 1, 2, 3, 0, time.UTC)
	legacyJSON, err := identity.MarshalRequest("test-app", "1.2.3", "实例-a", now)
	if err != nil {
		t.Fatal(err)
	}
	code, err := identity.MarshalRequestCode("test-app", "1.2.3", "实例-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(code, RequestCodePrefix) || strings.ContainsAny(code, "=\r\n ") {
		t.Fatalf("invalid one-line request code format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, RequestCodePrefix))
	if err != nil {
		t.Fatal(err)
	}
	var original, expanded map[string]any
	if json.Unmarshal(legacyJSON, &original) != nil || json.Unmarshal(payload, &expanded) != nil {
		t.Fatal("invalid request JSON")
	}
	if expanded["architecture"] != runtime.GOARCH || expanded["machineId"] != identity.MachineID {
		t.Fatal("request code did not include architecture and machine ID")
	}
	delete(expanded, "architecture")
	if !reflect.DeepEqual(expanded, original) {
		t.Fatal("request code changed the signed request fields")
	}
	if _, err := identity.MarshalRequestCode(strings.Repeat("a", 4096), "1.2.3", "default", now); err == nil {
		t.Fatal("accepted request larger than the paste field")
	}
}
