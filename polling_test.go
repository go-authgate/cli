package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const testAccessToken = "test-access-token"

func TestPollForToken_AuthorizationPending(t *testing.T) {
	attempts := atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)

		if attempts.Load() < 3 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{
				"error":             "authorization_pending",
				"error_description": "User has not yet authorized",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  testAccessToken,
			"refresh_token": "test-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	config := &oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{TokenURL: server.URL},
	}
	deviceAuth := &oauth2.DeviceAuthResponse{
		DeviceCode: "test-device-code",
		Interval:   1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token, err := pollForTokenWithProgress(ctx, config, deviceAuth)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if token.AccessToken != testAccessToken {
		t.Errorf("access token = %q, want %q", token.AccessToken, testAccessToken)
	}
	if attempts.Load() < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts.Load())
	}
}

func TestPollForToken_SlowDown(t *testing.T) {
	attempts := atomic.Int32{}
	slowDownCount := atomic.Int32{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)

		if attempts.Load() <= 2 {
			slowDownCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{
				"error":             "slow_down",
				"error_description": "Polling too frequently",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		if attempts.Load() < 5 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{
				"error":             "authorization_pending",
				"error_description": "User has not yet authorized",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  testAccessToken,
			"refresh_token": "test-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	config := &oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{TokenURL: server.URL},
	}
	deviceAuth := &oauth2.DeviceAuthResponse{
		DeviceCode: "test-device-code",
		Interval:   1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	token, err := pollForTokenWithProgress(ctx, config, deviceAuth)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if token.AccessToken != testAccessToken {
		t.Errorf("access token = %q, want %q", token.AccessToken, testAccessToken)
	}
	if slowDownCount.Load() < 2 {
		t.Errorf("expected at least 2 slow_down responses, got %d", slowDownCount.Load())
	}
}

// pollForTokenErrorTest is a shared helper for tests that expect pollForTokenWithProgress
// to return a specific error when the server responds with a terminal OAuth error code.
func pollForTokenErrorTest(t *testing.T, errCode, errDesc, expectedMsg string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]string{
			"error":             errCode,
			"error_description": errDesc,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	config := &oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{TokenURL: server.URL},
	}
	deviceAuth := &oauth2.DeviceAuthResponse{
		DeviceCode: "test-device-code",
		Interval:   1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := pollForTokenWithProgress(ctx, config, deviceAuth)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != expectedMsg {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPollForToken_ExpiredToken(t *testing.T) {
	pollForTokenErrorTest(t,
		"expired_token",
		"Device code has expired",
		"device code expired, please restart the flow",
	)
}

func TestPollForToken_AccessDenied(t *testing.T) {
	pollForTokenErrorTest(t,
		"access_denied",
		"User denied the authorization request",
		"user denied authorization",
	)
}

func TestPollForToken_ContextTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]string{
			"error":             "authorization_pending",
			"error_description": "User has not yet authorized",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	config := &oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{TokenURL: server.URL},
	}
	deviceAuth := &oauth2.DeviceAuthResponse{
		DeviceCode: "test-device-code",
		Interval:   1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := pollForTokenWithProgress(ctx, config, deviceAuth)
	if err == nil {
		t.Fatal("expected context timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded in error chain, got: %v", err)
	}
}

func TestExchangeDeviceCode_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Errorf("unexpected grant_type: %s", r.FormValue("grant_type"))
		}
		if r.FormValue("device_code") != "test-device-code" {
			t.Errorf("unexpected device_code: %s", r.FormValue("device_code"))
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  testAccessToken,
			"refresh_token": "test-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	token, err := exchangeDeviceCode(ctx, server.URL, "test-client", "test-device-code")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if token.AccessToken != testAccessToken {
		t.Errorf("access token = %q, want %q", token.AccessToken, testAccessToken)
	}
	if token.RefreshToken != "test-refresh-token" {
		t.Errorf("refresh token = %q, want %q", token.RefreshToken, "test-refresh-token")
	}
}
