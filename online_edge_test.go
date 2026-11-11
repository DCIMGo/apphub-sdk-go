package apphubsdk

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func activationJSON(content []byte, digest string, size int) map[string]any {
	return map[string]any{
		"code": 0, "message": "success", "traceId": "trace-activation",
		"data": map[string]any{"activationId": "act_1", "licenseId": "lic_1", "licenseItemId": "li_1", "licenseRevision": 1,
			"file": map[string]any{"name": "app.license", "content": base64.RawURLEncoding.EncodeToString(content), "size": size, "sha256": digest}},
	}
}

func leaseJSON(content []byte, revision int64) map[string]any {
	return map[string]any{
		"code": 0, "message": "success", "traceId": "trace-lease",
		"data": map[string]any{"authorizationId": "auth_1", "leaseId": fmt.Sprintf("lease_%d", revision), "revision": revision,
			"leaseToken": base64.RawURLEncoding.EncodeToString(content), "status": "active"},
	}
}

func TestAuthorizeOnlineInstallsAndRenewsLease(t *testing.T) {
	fixture := newSDKTestFixture(t)
	clock := fixture.now
	config := fixture.config(t, func() time.Time { return clock })
	var renewCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Idempotency-Key") == "" || request.Header.Get("Content-Type") != "application/json" {
			t.Error("missing request headers")
		}
		if request.URL.Path == "/api/v1/online/authorize" && request.Header.Get("Idempotency-Key") != "lease-request-0001" {
			t.Error("caller idempotency key was not preserved")
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["protocolVersion"] != protocolVersion || body["appId"] != "go-dcim" || body["instanceId"] != "primary" {
			t.Errorf("unexpected request metadata: %#v", body)
		}
		payload := fixture.leasePayload()
		if request.URL.Path == "/api/v1/online/renew" {
			payload.Revision = int64(renewCount.Add(1)) + 1
			payload.LeaseID = fmt.Sprintf("lease_%d", payload.Revision)
			payload.RenewAfter = clock.Add(2 * time.Hour)
			payload.ExpiresAt = clock.Add(4 * time.Hour)
			payload.GraceUntil = clock.Add(5 * time.Hour)
		} else if request.URL.Path != "/api/v1/online/authorize" {
			http.NotFound(response, request)
			return
		}
		content := fixture.signLease(t, payload)
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(leaseJSON(content, payload.Revision))
	}))
	defer server.Close()
	config.ServerURL = server.URL
	sdk, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	status, err := sdk.AuthorizeOnline(context.Background(), AuthorizeRequest{ActivationCode: "activation-code", IdempotencyKey: "lease-request-0001"})
	if err != nil || status.LeaseState != "authorized" || status.LeaseID != "lease_1" {
		t.Fatalf("authorize failed: %#v %v", status, err)
	}
	clock = fixture.now.Add(90 * time.Minute)
	status, err = sdk.RenewOnline(context.Background())
	if err != nil || status.LeaseState != "authorized" || status.LeaseRevision != 2 || status.LeaseID != "lease_2" {
		t.Fatalf("renew failed: %#v %v", status, err)
	}
	if renewCount.Load() != 1 {
		t.Fatalf("renew count = %d", renewCount.Load())
	}
}

func TestRenewOnlineFallsBackToCachedLeaseDuringNetworkFailure(t *testing.T) {
	fixture := newSDKTestFixture(t)
	clock := fixture.now.Add(150 * time.Minute)
	config := fixture.config(t, func() time.Time { return clock })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Error(response, "temporary failure", http.StatusBadGateway)
	}))
	defer server.Close()
	config.ServerURL = server.URL
	sdk, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	content := fixture.signLease(t, fixture.leasePayload())
	if err := os.WriteFile(config.LicensePath+".lease", content, 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := sdk.RenewOnline(context.Background())
	if err == nil || status.LeaseState != "grace" {
		t.Fatalf("cached grace fallback failed: %#v %v", status, err)
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) == false || apiErr.HTTPStatus != http.StatusBadGateway {
		t.Fatalf("expected API error, got %T %v", err, err)
	}
}

func TestActivateOnceValidatesDigestSizeAndEnvelope(t *testing.T) {
	fixture := newSDKTestFixture(t)
	content := fixture.signLicense(t, fixture.licensePayload())
	digest := sha256.Sum256(content)
	cases := []struct {
		name string
		file map[string]any
	}{
		{"size mismatch", map[string]any{"content": base64.RawURLEncoding.EncodeToString(content), "size": len(content) + 1, "sha256": hex.EncodeToString(digest[:])}},
		{"digest mismatch", map[string]any{"content": base64.RawURLEncoding.EncodeToString(content), "size": len(content), "sha256": strings.Repeat("0", 64)}},
		{"invalid content", map[string]any{"content": "%%%", "size": 3, "sha256": hex.EncodeToString(digest[:])}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				_ = json.NewEncoder(response).Encode(map[string]any{"code": 0, "data": map[string]any{"file": test.file}})
			}))
			defer server.Close()
			config := fixture.config(t, nil)
			config.ServerURL = server.URL
			sdk, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sdk.ActivateOnce(context.Background(), ActivateRequest{IdempotencyKey: "activation-request-0001"}); err == nil {
				t.Fatal("invalid activation response accepted")
			}
		})
	}
}

func TestOnlineAPIErrorAndResponseSizeLimit(t *testing.T) {
	fixture := newSDKTestFixture(t)
	tests := []struct {
		name       string
		handler    http.Handler
		wantStatus int
		wantAPI    bool
	}{
		{"http error", http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(response).Encode(map[string]any{"code": 40101, "message": "denied", "traceId": "trace-denied", "data": map[string]any{"reason": "activation_denied"}})
		}), http.StatusUnauthorized, true},
		{"business error", http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(response).Encode(map[string]any{"code": 40001, "message": "bad request", "traceId": "trace-bad", "data": map[string]any{}})
		}), http.StatusOK, true},
		{"response too large", http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write(make([]byte, maxLocalArtifactSize+1))
		}), http.StatusOK, false},
		{"malformed response", http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write([]byte("not-json"))
		}), http.StatusOK, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			config := fixture.config(t, nil)
			config.ServerURL = server.URL
			sdk, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			_, err = sdk.AuthorizeOnline(context.Background(), AuthorizeRequest{IdempotencyKey: "lease-request-0001"})
			if err == nil {
				t.Fatal("invalid response accepted")
			}
			var apiErr *APIError
			if errors.As(err, &apiErr) != test.wantAPI {
				t.Fatalf("API error classification mismatch: %T %v", err, err)
			}
			if test.wantAPI && apiErr.HTTPStatus != test.wantStatus {
				t.Fatalf("HTTP status = %d, want %d", apiErr.HTTPStatus, test.wantStatus)
			}
		})
	}
}

func TestHTTPClientBlocksCrossOriginAuthorizationRedirect(t *testing.T) {
	fixture := newSDKTestFixture(t)
	targetCalled := atomic.Bool{}
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		targetCalled.Store(true)
		http.Error(response, "unexpected", http.StatusInternalServerError)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL+"/api/v1/activation/issue", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	config := fixture.config(t, nil)
	config.ServerURL = redirector.URL
	sdk, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sdk.ActivateOnce(context.Background(), ActivateRequest{IdempotencyKey: "activation-request-0001"})
	if err == nil || !strings.Contains(err.Error(), "cross-origin") {
		t.Fatalf("cross-origin redirect was not blocked: %v", err)
	}
	if targetCalled.Load() {
		t.Fatal("authorization request reached redirect target")
	}
}

func TestSecureRedirectRules(t *testing.T) {
	original, _ := http.NewRequest(http.MethodPost, "https://apphub.example.com/api", nil)
	if err := secureRedirect(original, []*http.Request{original, original, original}); err == nil {
		t.Fatal("redirect limit not enforced")
	}
	insecure, _ := http.NewRequest(http.MethodPost, "http://apphub.example.com/api", nil)
	if err := secureRedirect(insecure, nil); err == nil {
		t.Fatal("insecure redirect accepted")
	}
	loopback, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:1234/api", nil)
	if err := secureRedirect(loopback, nil); err != nil {
		t.Fatalf("loopback development redirect blocked: %v", err)
	}
}

func TestSDKOnlineAndLocalMethodsRejectNilContext(t *testing.T) {
	fixture := newSDKTestFixture(t)
	sdk, err := New(fixture.config(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		call func() error
	}{
		{name: "machine id", call: func() error { _, err := sdk.MachineID(nil); return err }},
		{name: "machine request", call: func() error { _, err := sdk.MachineRequest(nil); return err }},
		{name: "local import", call: func() error { _, err := sdk.ImportLicense(nil, []byte("license")); return err }},
		{name: "local verify", call: func() error { _, err := sdk.VerifyLocal(nil); return err }},
		{name: "one-time activation", call: func() error { _, err := sdk.ActivateOnce(nil, ActivateRequest{}); return err }},
		{name: "online authorize", call: func() error { _, err := sdk.AuthorizeOnline(nil, AuthorizeRequest{}); return err }},
		{name: "online renew", call: func() error { _, err := sdk.RenewOnline(nil); return err }},
		{name: "cached lease verify", call: func() error { _, err := sdk.VerifyOnlineLease(nil); return err }},
		{name: "update check", call: func() error { _, err := sdk.CheckUpdate(nil, UpdateCheckRequest{}); return err }},
		{name: "auto renew", call: func() error { return sdk.StartAutoRenew(nil) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil || err.Error() != "context is required" {
				t.Fatalf("nil context error = %v", err)
			}
		})
	}
}
