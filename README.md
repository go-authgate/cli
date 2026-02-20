# Authgate CLI

[![Lint and Testing](https://github.com/go-authgate/cli/actions/workflows/testing.yml/badge.svg)](https://github.com/go-authgate/cli/actions/workflows/testing.yml)
[![Trivy Security Scan](https://github.com/go-authgate/cli/actions/workflows/security.yml/badge.svg)](https://github.com/go-authgate/cli/actions/workflows/security.yml)

A production-ready OAuth 2.0 CLI that automatically selects between **Authorization Code Flow with PKCE** (browser-based) and **Device Authorization Grant** (headless/SSH) depending on the runtime environment. No manual configuration required.

This mirrors the authentication strategy used by GitHub CLI, Azure CLI, and Google Cloud SDK.

## Table of Contents

- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Authentication Flows](#authentication-flows)
- [Token Storage](#token-storage)

---

## How It Works

### Flow selection

```mermaid
flowchart TD
    classDef start   fill:#6366f1,color:#fff,stroke:#4f46e5
    classDef pkce    fill:#22c55e,color:#fff,stroke:#16a34a
    classDef device  fill:#f59e0b,color:#000,stroke:#d97706
    classDef done    fill:#3b82f6,color:#fff,stroke:#2563eb
    classDef check   fill:#f8fafc,color:#1e293b,stroke:#94a3b8

    START([CLI Launch]):::start --> FORCE_FLAG{--device / --no-browser?}:::check

    FORCE_FLAG -->|Yes| DEVICE([Device Code Flow]):::device
    FORCE_FLAG -->|No| SSH{SSH without display?}:::check

    SSH -->|Yes| DEVICE
    SSH -->|No| LINUX{Linux, no display?}:::check

    LINUX -->|Yes| DEVICE
    LINUX -->|No| PORT{Callback port free?}:::check

    PORT -->|In use| DEVICE
    PORT -->|Free| PKCE([Auth Code + PKCE]):::pkce

    PKCE --> BROWSER{Browser opens?}:::check
    BROWSER -->|Failed| DEVICE
    BROWSER -->|Success| CALLBACK{Callback received?}:::check

    CALLBACK -->|Timeout (2 min)| DEVICE
    CALLBACK -->|Received| DONE([Tokens Saved]):::done

    DEVICE --> DONE
```

### Token lifecycle

On each run the CLI follows this order:

1. **Load cached tokens** — read from `TOKEN_FILE` keyed by `CLIENT_ID`
2. **Valid access token** — use it directly, skip authentication
3. **Expired access token** — attempt a silent refresh with the refresh token
4. **Expired/missing refresh token** — trigger full re-authentication (browser or device flow)
5. **After any successful auth** — verify token at `/oauth/tokeninfo`, then demonstrate auto-refresh on `401`

---

## Prerequisites

- Go 1.24+
- A running [AuthGate server](../README.md)
- The `CLIENT_ID` UUID shown in the server startup logs

---

## Quick Start

```bash
cp .env.example .env
# Edit .env: set CLIENT_ID (and SERVER_URL if not localhost)

go run .
```

To build a binary:

```bash
make build
# Binary is written to bin/cli
```

---

## Configuration

Configuration is resolved in priority order: **CLI flag → environment variable → default**.

### Environment variables

| Variable        | Default                 | Description                                  |
| --------------- | ----------------------- | -------------------------------------------- |
| `SERVER_URL`    | `http://localhost:8080` | AuthGate server base URL                     |
| `CLIENT_ID`     | _(required)_            | OAuth client ID (UUID from server logs)      |
| `CLIENT_SECRET` | _(empty)_               | Client secret — omit for public/PKCE clients |
| `CALLBACK_PORT` | `8888`                  | Local port for the redirect callback server  |
| `SCOPE`         | `read write`            | Space-separated OAuth scopes                 |
| `TOKEN_FILE`    | `.authgate-tokens.json` | Path to the token cache file                 |

### CLI flags

| Flag              | Env equivalent  | Description                               |
| ----------------- | --------------- | ----------------------------------------- |
| `--server-url`    | `SERVER_URL`    | AuthGate server URL                       |
| `--client-id`     | `CLIENT_ID`     | OAuth client ID                           |
| `--client-secret` | `CLIENT_SECRET` | Client secret (confidential clients only) |
| `--redirect-uri`  | —               | Override computed redirect URI            |
| `--port`          | `CALLBACK_PORT` | Local callback port                       |
| `--scope`         | `SCOPE`         | OAuth scopes                              |
| `--token-file`    | `TOKEN_FILE`    | Token cache file path                     |
| `--device`        | —               | Force Device Code Flow                    |
| `--no-browser`    | —               | Alias for `--device`                      |

### Usage examples

```bash
# Auto-detect flow (default)
./bin/cli

# Force Device Code Flow (useful in scripts or CI)
./bin/cli --device
./bin/cli --no-browser

# Override server and client
./bin/cli --server-url https://auth.example.com --client-id <uuid>

# Use a non-default callback port
./bin/cli --port 9999
```

---

## Authentication Flows

### Authorization Code Flow with PKCE (browser)

Used when a local browser and a free callback port are available. Suitable for developer workstations.

```
=== AuthGate CLI ===
Client mode : public (PKCE)
Server URL  : http://localhost:8080
Client ID   : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

Auth method : Authorization Code Flow (browser)
Step 1: Opening browser for authorization...

  http://localhost:8080/oauth/authorize?...

Browser opened. Please complete authorization in your browser.
Step 2: Waiting for callback on http://localhost:8888/callback ...
Authorization code received!
Step 3: Exchanging authorization code for tokens...
Tokens saved to .authgate-tokens.json
```

**Security properties:**

- PKCE (RFC 7636) — prevents authorization code interception
- `state` parameter — CSRF protection on the callback
- Callback server binds to `127.0.0.1` only
- 2-minute timeout; falls back to Device Code Flow automatically

### Device Authorization Grant (headless/SSH)

Used when no browser is available: SSH sessions without display forwarding, Linux servers, CI environments.

```
=== AuthGate CLI ===
Auth method : Device Code Flow (SSH session without display forwarding)
Step 1: Requesting device code...

----------------------------------------
Please open this link to authorize:
http://localhost:8080/device?user_code=ABC-12345

Or visit : http://localhost:8080/device
And enter: ABC-12345
----------------------------------------

Step 2: Waiting for authorization...............
Authorization successful!
Tokens saved to .authgate-tokens.json
```

**Polling behavior:**

- Respects the server-specified polling interval (default 5 s)
- Implements RFC 8628 exponential backoff on `slow_down` (up to 60 s)

### Public vs. confidential clients

| Mode          | `CLIENT_SECRET` | Token exchange        |
| ------------- | --------------- | --------------------- |
| Public (PKCE) | Not set         | Sends `code_verifier` |
| Confidential  | Set             | Sends `client_secret` |

Public/PKCE is the recommended mode for CLI tools.

---

## Token Storage

Tokens are saved to `TOKEN_FILE` (default `.authgate-tokens.json`) and keyed by `CLIENT_ID`, so the same file can hold credentials for multiple clients.

```json
{
  "tokens": {
    "<client-id>": {
      "access_token": "...",
      "refresh_token": "...",
      "token_type": "Bearer",
      "expires_at": "2026-01-01T00:00:00Z",
      "client_id": "<client-id>",
      "flow": "browser"
    }
  }
}
```

The `flow` field records whether `browser` or `device` was used.

**Concurrent write safety:** token writes use a `.lock` file with a 30-second stale-lock timeout, ensuring multiple processes can share the same token file without corruption.

**File permissions:** written as `0600` (owner read/write only).

---

## Development

### Prerequisites

```bash
# Install development tools
make install-golangci-lint   # linter
make install-templ           # template code generator (if used)
```

### Common commands

```bash
make build          # Build binary → bin/cli
make test           # Run tests with coverage
make coverage       # Open coverage report in browser
make lint           # Run golangci-lint
make fmt            # Format code
make dev            # Hot reload with air
make clean          # Remove bin/, release/, coverage.txt
make rebuild        # clean + build
```

### Cross-platform builds

```bash
make build_linux_amd64    # Linux x86-64 → release/linux/amd64/cli
make build_linux_arm64    # Linux ARM64  → release/linux/arm64/cli
```
