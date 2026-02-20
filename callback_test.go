package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type callbackServerResult struct {
	storage *TokenStorage
	err     error
}

// startCallbackServerAsync starts the callback server in a goroutine and
// returns a channel that will receive the result (storage or error).
func startCallbackServerAsync(
	t *testing.T, ctx context.Context, port int, state string,
	exchangeFn func(context.Context, string) (*TokenStorage, error),
) chan callbackServerResult {
	t.Helper()
	ch := make(chan callbackServerResult, 1)
	go func() {
		storage, err := startCallbackServer(ctx, port, state, exchangeFn)
		ch <- callbackServerResult{storage, err}
	}()
	// Give the server a moment to bind.
	time.Sleep(50 * time.Millisecond)
	return ch
}

// noExchangeFn returns an exchange function that fails the test if called.
func noExchangeFn(t *testing.T) func(context.Context, string) (*TokenStorage, error) {
	t.Helper()
	return func(_ context.Context, _ string) (*TokenStorage, error) {
		t.Error("exchangeFn should not be called")
		return nil, fmt.Errorf("should not be called")
	}
}

// stubExchangeFn returns an exchange function that validates the received code
// and returns a minimal TokenStorage on success.
func stubExchangeFn(wantCode string) func(context.Context, string) (*TokenStorage, error) {
	return func(_ context.Context, gotCode string) (*TokenStorage, error) {
		if gotCode != wantCode {
			return nil, fmt.Errorf("unexpected code: got %q, want %q", gotCode, wantCode)
		}
		return &TokenStorage{AccessToken: "test-token"}, nil
	}
}

func TestCallbackServer_Success(t *testing.T) {
	const port = 19101
	state := "test-state-success"

	ch := startCallbackServerAsync(
		t,
		context.Background(),
		port,
		state,
		stubExchangeFn("mycode123"),
	)

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?code=mycode123&state=%s",
		port, state,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Authorization Successful") {
		t.Errorf("expected success page, got: %s", string(body))
	}

	select {
	case result := <-ch:
		if result.err != nil {
			t.Errorf("expected success, got error: %v", result.err)
		}
		if result.storage == nil {
			t.Error("expected non-nil storage")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_StateMismatch(t *testing.T) {
	const port = 19102
	state := "expected-state"

	ch := startCallbackServerAsync(t, context.Background(), port, state, noExchangeFn(t))

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?code=mycode&state=wrong-state",
		port,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Authorization Failed") {
		t.Errorf("expected failure page for state mismatch, got: %s", string(body))
	}

	select {
	case result := <-ch:
		if result.err == nil {
			t.Error("expected error for state mismatch, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_OAuthError(t *testing.T) {
	const port = 19103
	state := "state-for-error"

	ch := startCallbackServerAsync(t, context.Background(), port, state, noExchangeFn(t))

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?error=access_denied&error_description=User+denied&state=%s",
		port, state,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Authorization Failed") {
		t.Errorf("expected failure page for access_denied, got: %s", string(body))
	}

	select {
	case result := <-ch:
		if result.err == nil {
			t.Error("expected error for access_denied, got nil")
		}
		if !strings.Contains(result.err.Error(), "access_denied") {
			t.Errorf("expected error to mention access_denied, got: %v", result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_ExchangeFailure(t *testing.T) {
	const port = 19106
	state := "state-for-exchange-failure"

	ch := startCallbackServerAsync(t, context.Background(), port, state,
		func(_ context.Context, _ string) (*TokenStorage, error) {
			return nil, fmt.Errorf("unauthorized_client: unauthorized_client")
		})

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?code=mycode&state=%s",
		port, state,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Authorization Failed") {
		t.Errorf("expected failure page for exchange error, got: %s", string(body))
	}

	select {
	case result := <-ch:
		if result.err == nil {
			t.Error("expected error for exchange failure, got nil")
		}
		if !strings.Contains(result.err.Error(), "unauthorized_client") {
			t.Errorf("expected error to mention unauthorized_client, got: %v", result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_DoubleCallback(t *testing.T) {
	const port = 19105
	state := "test-state-double"

	ch := startCallbackServerAsync(t, context.Background(), port, state, stubExchangeFn("mycode"))

	url := fmt.Sprintf("http://127.0.0.1:%d/callback?code=mycode&state=%s", port, state)

	done := make(chan error, 2)
	for range 2 {
		go func() {
			resp, err := http.Get(url) //nolint:noctx,gosec
			if err == nil {
				resp.Body.Close()
			}
			done <- err
		}()
	}

	for range 2 {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("a callback handler goroutine hung on channel send")
		}
	}

	select {
	case result := <-ch:
		if result.err != nil {
			t.Errorf("expected success, got error: %v", result.err)
		}
		if result.storage == nil {
			t.Error("expected non-nil storage")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_MissingCode(t *testing.T) {
	const port = 19104
	state := "state-for-missing-code"

	ch := startCallbackServerAsync(t, context.Background(), port, state, noExchangeFn(t))

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?state=%s",
		port, state,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	select {
	case result := <-ch:
		if result.err == nil {
			t.Error("expected error for missing code, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}
