# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Authgate CLI is a production-ready OAuth 2.0 authentication library for Go CLI applications. It automatically selects between Authorization Code Flow with PKCE (browser-based) and Device Authorization Grant (headless/SSH) based on the runtime environment.

## Development Commands

### Building and Running

```bash
make build          # Build binary → bin/authgate-cli
go run .            # Run directly without building
make rebuild        # Clean and rebuild
make dev            # Hot reload with air
```

### Testing

```bash
make test           # Run all tests with coverage
make coverage       # Open coverage report in browser
go test -v -run TestFunctionName  # Run a single test
```

### Code Quality

```bash
make lint           # Run golangci-lint
make fmt            # Format code
make check-tools    # Verify all required tools are installed
```

### Cross-Platform Builds

```bash
make build_linux_amd64    # Linux x86-64 → release/linux/amd64/authgate-cli
make build_linux_arm64    # Linux ARM64  → release/linux/arm64/authgate-cli
```

### Template Generation

This project uses `templ` for template code generation:

```bash
make generate       # Compile .templ files
make watch          # Watch mode for automatic regeneration
```

## Architecture

### OAuth Flow Selection Logic

The CLI implements a hierarchical decision tree to select the appropriate OAuth flow (`main.go:authenticate()`):

1. **Forced Device Flow**: `--device` or `--no-browser` flags → Device Code Flow
2. **Environment Detection** (`detect.go:checkBrowserAvailability()`):
   - SSH without display forwarding → Device Code Flow
   - Linux with no DISPLAY/WAYLAND_DISPLAY → Device Code Flow
   - Callback port (default 8888) unavailable → Device Code Flow
3. **Browser Flow Attempt**: If all checks pass → Authorization Code + PKCE
   - If `openBrowser()` fails → Immediate fallback to Device Code Flow
   - If callback times out (2 min) → Fallback to Device Code Flow

### Core Components

**Configuration (`config.go`)**

- Config resolution priority: CLI flags → environment variables → defaults
- Validates `SERVER_URL` format and warns on HTTP (non-HTTPS) usage
- Requires `CLIENT_ID` (UUID from AuthGate server logs)
- Public client mode when `CLIENT_SECRET` is empty (triggers PKCE)

**Token Management (`tokens.go`)**

- Multi-client token storage: single JSON file keyed by `CLIENT_ID`
- File locking (`filelock.go`) prevents concurrent write corruption:
  - Uses `.lock` file with 30-second stale-lock timeout
  - Atomic write via temp file + rename
  - File permissions: `0600` (owner read/write only)
- Token refresh preserves old refresh token if server doesn't return a new one

**Browser Flow (`browser_flow.go`, `callback.go`)**

- PKCE implementation (`pkce.go`): SHA-256 code challenge
- Local callback server on `127.0.0.1` only (security: no external binding)
- 2-minute callback timeout with automatic Device Flow fallback
- CSRF protection via `state` parameter validation
- In-server token exchange: callback handler performs code→token exchange before returning success page

**Device Flow (`device_flow.go`)**

- RFC 8628 Device Authorization Grant
- Polling with exponential backoff on `slow_down` (max 60s interval)
- Progress dots printed every 2 seconds
- Handles: `authorization_pending`, `slow_down`, `expired_token`, `access_denied`

**Environment Detection (`detect.go`)**

- Two-stage check: environment signals + port availability
- SSH detection: `SSH_TTY`, `SSH_CLIENT`, `SSH_CONNECTION` env vars
- Display detection: `DISPLAY` (X11) or `WAYLAND_DISPLAY`
- Port binding test: attempts to bind callback port before committing to browser flow

### Token Lifecycle

On each run (`main.go:run()`):

1. Load cached tokens from `TOKEN_FILE`
2. If access token valid → use directly
3. If access token expired → attempt refresh with `refresh_token`
4. If refresh fails → trigger full re-authentication
5. After successful auth → verify at `/oauth/tokeninfo`
6. Demonstrate auto-refresh: intentionally trigger 401, refresh, and retry

### Error Handling

- `ErrRefreshTokenExpired`: Sentinel error for expired refresh tokens
- `ErrCallbackTimeout`: Distinguishes timeout from other auth failures for fallback logic
- OAuth errors parsed from JSON response: `error` and `error_description` fields
- HTTP retry client (`github.com/appleboy/go-httpretry`) wraps all OAuth requests

## Key Implementation Details

### Public vs. Confidential Clients

- **Public (PKCE)**: No `CLIENT_SECRET` → sends `code_verifier` in token exchange
- **Confidential**: `CLIENT_SECRET` set → sends both `client_secret` and `code_verifier`

### Browser Opening

Browser opening is platform-specific (`browser.go`):

- macOS: `open`
- Linux: `xdg-open`
- Windows: `cmd /c start`
- Failures are handled gracefully with immediate Device Flow fallback (no user retry required)

### Testing Strategy

- 6 test files covering: PKCE generation, callback server, file locking, environment detection, device flow polling
- Tests use in-memory servers and context cancellation for timeout simulation
- Mock OAuth responses for error path testing

## Configuration Requirements

### Minimum Setup

```bash
SERVER_URL=http://localhost:8080  # AuthGate server
CLIENT_ID=<uuid-from-server-logs> # Required
```

### Optional Configuration

- `CLIENT_SECRET`: For confidential clients (omit for public/PKCE)
- `CALLBACK_PORT`: Default 8888 (browser flow only)
- `SCOPE`: Default "read write"
- `TOKEN_FILE`: Default `.authgate-tokens.json`
- `REDIRECT_URI`: Computed as `http://localhost:{PORT}/callback` by default

## Security Considerations

- PKCE prevents authorization code interception attacks
- CSRF protection via `state` parameter
- Callback server binds to `127.0.0.1` only (no external access)
- Token files written with `0600` permissions
- TLS 1.2+ enforced for HTTPS connections
- Warns when using HTTP (only safe for local development)

## Common Development Scenarios

### Adding a New OAuth Endpoint

1. Add endpoint constants to `config.go` if needed
2. Implement request function (follow patterns in `browser_flow.go` or `device_flow.go`)
3. Use `retryClient.DoWithContext()` for all HTTP requests
4. Parse OAuth errors with `ErrorResponse` struct
5. Add unit tests using mock HTTP servers

### Modifying Token Storage

- Token storage uses a map structure to support multiple clients
- All writes must acquire file lock via `acquireFileLock()`
- Use atomic write pattern: write to `.tmp` file, then rename
- Update `TokenStorage` struct if adding new fields (remember JSON tags)

### Extending Environment Detection

- Add new checks to `detect.go:checkBrowserAvailability()`
- Return `BrowserAvailability{Available: false, Reason: "..."}` for new failure cases
- Document the new detection logic in the function comment

## Dependencies

- `github.com/google/uuid`: UUID parsing and validation
- `github.com/joho/godotenv`: `.env` file loading
- `github.com/appleboy/go-httpretry`: HTTP retry with backoff
- `golang.org/x/oauth2`: Device flow types and token structures
- Go 1.24+ required
