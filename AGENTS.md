# AGENTS.md

This document contains essential knowledge for agents working in the `ldap4gin` codebase.

## Project Overview

`ldap4gin` is a Go module that provides LDAP authentication integration for the Gin web framework. It handles user authentication against an LDAP server, session management, and group extraction. The module is designed to be used as a dependency in Gin-based applications.

## Essential Commands

### Development and Testing

```bash
# Install dependencies
make deps

# Run tests with verbose output
make test

# Run linter (gofmt, golint, go vet)
make lint

# Run all checks (lint + test)
make check

# Start the example application
make run

# Clean build artifacts
make clean
```

### Project Information

```bash
# Check for vulnerabilities using govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
make vuln
```

## Code Organization

- `authenticator.go`: Main implementation of the `Authenticator` struct and its methods (`Authorize`, `Extract`, `Logout`, `Close`)
- `options.go`: Configuration options for the authenticator
- `new.go`: Constructor function `New()` for creating an `Authenticator` instance
- `ping.go`: Connection management and health checking (`Ping`, `redial`)
- `user.go`: User profile model and helper functions
- `group.go`: Group model
- `errors.go`: Custom error definitions
- `example/`: Complete working example with Docker Compose setup

## Architecture and Control Flow

The authentication flow follows these steps:

1. **Authorization**: `Authorize()` method attempts to bind to LDAP with the provided username and password
   - Validates username format using regex
   - Formats DN using `UserBaseTpl` template
   - Attempts LDAP bind operation
   - On success, retrieves user profile and optionally groups
   - Stores user profile in session

2. **Extraction**: `Extract()` method retrieves user profile from session
   - Checks for cached profile in Gin context metadata first
   - If not found, retrieves from session
   - If session exists but has expired (based on `TTL`), refreshes from LDAP
   - Caches refreshed profile in context metadata for the request duration

3. **Connection Management**: The authenticator maintains a persistent LDAP connection
   - `Ping()` checks connection health and re-establishes if needed
   - Uses `redial()` to reconnect when connection is lost
   - Supports both plain LDAP and LDAPS connections

4. **Group Extraction**: When `ExtractGroups` is enabled
   - Uses a dedicated readonly LDAP user to search for user's group memberships
   - Searches in the configured `GroupsOU` organizational unit
   - Parses group information (GID, name, description)

## Key Patterns and Conventions

### Error Handling

The module defines specific error types in `errors.go`:
- `ErrUnauthorized`: User is not authenticated
- `ErrMalformed`: Username format is invalid
- `ErrInvalidCredentials`: LDAP bind failed due to wrong password
- `ErrNotFound`: User not found in LDAP
- `ErrMultipleAccount`: Multiple user entries found (should not happen with proper LDAP schema)
- `ErrReadonlyWrongCredentials`: Readonly user credentials are incorrect

### Configuration

The `Options` struct in `options.go` controls behavior:
- `Debug`: Enables debug logging
- `TTL`: Session cache duration before refresh from LDAP
- `ConnectionString`: LDAP server address (ldap:// or ldaps://)
- `TLS`: TLS configuration
- `StartTLS`: Whether to use StartTLS command
- `ReadonlyDN`/`ReadonlyPasswd`: Credentials for readonly user to query group memberships
- `UserBaseTpl`: Template for constructing user DNs (e.g., "uid=%s,ou=people,dc=example,dc=com")
- `ExtraFields`: Additional LDAP attributes to retrieve
- `ExtractGroups`: Whether to extract group memberships
- `GroupsOU`: Organizational unit containing groups
- `LogDebugFunc`: Custom debug logging function

### Session Management

- Uses `github.com/gin-contrib/sessions` for session storage
- Stores user profile under `SessionKeyName` ("ldap4gin_user")
- Caches user profile in Gin context metadata under `MetadataKeyName` ("ldap4gin_meta") for the duration of the request
- Session size limitations are a concern when storing large user profiles in cookie-based sessions

### OpenTelemetry Integration

The module includes OpenTelemetry tracing:
- Uses `go.opentelemetry.io/otel` for distributed tracing
- Creates spans for key operations (`bindAsUser`, `attachGroups`, `reload`, `redial`, `ping`)
- Records attributes like username, DN, and trace IDs in logs
- The example application demonstrates OTLP HTTP tracing setup instead of the deprecated Jaeger exporter

## Testing Approach

- Unit tests in `unit_test.go` cover core functionality
- Tests verify:
  - Successful and failed authentication
  - User profile extraction
  - Group extraction
  - Session management
  - Error handling for various LDAP error conditions
- The example application serves as integration test

## Important Gotchas

1. **Session Size Limits**: When using cookie-based sessions (default in the example), be aware that large user profiles with many `ExtraFields` or groups may exceed cookie size limits. Consider using server-side session storage for production.

2. **Connection State**: The `Authenticator` maintains a single LDAP connection that is reused across requests. The connection is automatically re-established if lost, but this adds latency to the first operation after a disconnect.

3. **Readonly User Requirements**: Group extraction requires a dedicated readonly user with appropriate permissions to read the groups organizational unit. This user's credentials are configured in the `Options`.

4. **Username Validation**: Usernames are validated against a regex pattern (defined in `user.go` as `usernameRegexp`) before LDAP operations. This prevents LDAP injection attacks but may need adjustment for non-standard username formats.

5. **Field Name Case Sensitivity**: LDAP attribute names in the code use mixed case (e.g., `givenName`, `cn`) but are mapped to lowercase in the actual LDAP queries. Ensure consistency when adding `ExtraFields`.

6. **OTLP Tracing**: The example uses OTLP HTTP tracing instead of the deprecated Jaeger exporter. Traces are sent to http://127.0.0.1:4318/v1/traces over HTTP.

7. **Mutex Usage**: The `Authenticator` methods are protected by a mutex (`mu`) to ensure thread safety, as LDAP connections are not inherently thread-safe.

8. **TTL and Caching**: The `TTL` setting controls how often user profiles are refreshed from LDAP. Set this based on how frequently user attributes change and your performance requirements.

## Development Environment

The project includes a complete Docker Compose setup in `docker-compose.yml`:
- `jaeger`: Tracing backend (accessible at http://localhost:16686)
- `ldap`: OpenLDAP server (port 1389 mapped to host)
- `lam`: LDAP Account Manager web UI (accessible at http://localhost:8085)

To start the development environment:
```bash
docker-compose up -d
```

The example application connects to the LDAP server at `ldap://127.0.0.1:1389` and can be accessed at `http://localhost:3000`. The example application sends traces to http://127.0.0.1:4318/v1/traces.