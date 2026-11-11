package apphubsdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAutoRenewRenewsAndStops(t *testing.T) {
	fixture := newSDKTestFixture(t)
	initial := fixture.leasePayload()
	initial.IssuedAt = fixture.now.Add(-2 * time.Hour)
	initial.RenewAfter = fixture.now.Add(-time.Hour)
	initial.ExpiresAt = fixture.now.Add(time.Hour)
	initial.GraceUntil = fixture.now.Add(2 * time.Hour)
	renewed := fixture.leasePayload()
	renewed.LeaseID = "lease_2"
	renewed.Revision = 2
	renewed.IssuedAt = fixture.now.Add(-time.Minute)
	renewed.RenewAfter = fixture.now.Add(time.Hour)
	renewed.ExpiresAt = fixture.now.Add(2 * time.Hour)
	renewed.GraceUntil = fixture.now.Add(3 * time.Hour)
	renewedContent := fixture.signLease(t, renewed)
	renewedSignal := make(chan struct{}, 1)
	var renewCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/online/renew" {
			http.NotFound(response, request)
			return
		}
		renewCalls.Add(1)
		select {
		case renewedSignal <- struct{}{}:
		default:
		}
		_ = json.NewEncoder(response).Encode(leaseJSON(renewedContent, 2))
	}))
	defer server.Close()
	config := fixture.config(t, nil)
	config.ServerURL = server.URL
	config.AutoRenewInterval = 5 * time.Millisecond
	sdk, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.LicensePath+".lease", fixture.signLease(t, initial), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sdk.StartAutoRenew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sdk.StartAutoRenew(context.Background()); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("duplicate auto-renew accepted: %v", err)
	}
	select {
	case <-renewedSignal:
	case <-time.After(2 * time.Second):
		t.Fatal("automatic renewal did not call the server")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		content, readErr := os.ReadFile(config.LicensePath + ".lease")
		if readErr == nil {
			payload, _, verifyErr := sdk.(*client).keys.VerifyLease(content)
			if verifyErr == nil && payload.Revision == 2 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("renewed lease was not atomically installed")
		}
		time.Sleep(2 * time.Millisecond)
	}
	sdk.StopAutoRenew()
	sdk.StopAutoRenew()
	verified, verifyErr := sdk.(*client).verifyCachedLease(context.Background())
	if renewCalls.Load() < 1 || verifyErr != nil || verified.LeaseState != "authorized" || verified.LeaseRevision != 2 {
		t.Fatalf("auto renewal did not install lease: calls=%d status=%#v err=%v", renewCalls.Load(), verified, verifyErr)
	}
}

func TestAutoRenewRequiresContextAndCachedLease(t *testing.T) {
	fixture := newSDKTestFixture(t)
	sdk, err := New(fixture.config(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := sdk.StartAutoRenew(nil); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("nil context accepted: %v", err)
	}
	if err := sdk.StartAutoRenew(context.Background()); err == nil || !strings.Contains(err.Error(), "cached lease") {
		t.Fatalf("missing lease accepted: %v", err)
	}
}
