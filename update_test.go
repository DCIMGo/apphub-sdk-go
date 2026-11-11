package apphubsdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckUpdateSendsRuntimeIdentityAndReturnsRelease(t *testing.T) {
	fixture := newSDKTestFixture(t)
	config := fixture.config(t, nil)
	config.InstanceCredential = "credential-from-config"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/update/check" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		if request.Header.Get("Idempotency-Key") != "update-request-0001" {
			t.Fatalf("idempotency key = %q", request.Header.Get("Idempotency-Key"))
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		for key, want := range map[string]string{
			"protocolVersion":    protocolVersion,
			"sdkVersion":         Version,
			"appId":              "go-dcim",
			"currentVersion":     "2.1.0",
			"channel":            "beta",
			"os":                 "linux",
			"arch":               "amd64",
			"instanceId":         "primary",
			"instanceCredential": "credential-from-request",
		} {
			if body[key] != want {
				t.Errorf("%s = %#v, want %q", key, body[key], want)
			}
		}
		if body["machineId"] != fixture.machineID || body["requestId"] == "" || body["nonce"] == "" {
			t.Error("request identity metadata was not sent")
		}
		maintenance := fixture.now.Add(72 * time.Hour).Format(time.RFC3339)
		expires := fixture.now.Add(10 * time.Minute).Format(time.RFC3339)
		_ = json.NewEncoder(response).Encode(map[string]any{
			"code": 0, "message": "success", "data": map[string]any{
				"updateAvailable": true, "reason": "update_available", "updateTaskId": "task-1",
				"releaseId": "release-2", "version": "2.2.0", "channel": "beta",
				"mandatory": true, "securityUpdate": true, "supportsRollback": true,
				"releaseNotes": "修复授权校验", "knownIssues": "需要重启", "maintenanceUntil": maintenance,
				"manifestUrl": "/api/v1/update/releases/release-2/manifest", "manifestSha256": "abc123",
				"downloadToken": "download-token", "downloadTokenExpiresAt": expires,
			},
		})
	}))
	defer server.Close()
	config.ServerURL = server.URL
	sdk, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := sdk.CheckUpdate(context.Background(), UpdateCheckRequest{
		Channel: "beta", OS: "linux", Arch: "amd64", InstanceCredential: "credential-from-request",
		IdempotencyKey: "update-request-0001",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.UpdateAvailable || result.Reason != "update_available" || result.UpdateTaskID != "task-1" {
		t.Fatalf("unexpected decision: %#v", result)
	}
	if result.Release == nil || result.Release.ID != "release-2" || result.Release.Version != "2.2.0" || !result.Release.Mandatory || !result.Release.SecurityUpdate {
		t.Fatalf("unexpected release: %#v", result.Release)
	}
	if result.DownloadToken != "download-token" || result.DownloadTokenExpiresAt == nil {
		t.Fatalf("download token metadata missing: %#v", result)
	}
}

func TestCheckUpdateDefaultsPlatformAndRejectsMissingServer(t *testing.T) {
	fixture := newSDKTestFixture(t)
	sdk, err := New(fixture.config(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdk.CheckUpdate(context.Background(), UpdateCheckRequest{}); err == nil {
		t.Fatal("missing server URL accepted")
	}
	if _, err := sdk.CheckUpdate(nil, UpdateCheckRequest{}); err == nil {
		t.Fatal("nil context accepted")
	}
}
