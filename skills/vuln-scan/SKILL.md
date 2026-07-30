# vuln-scan

## Description

This skill scans the codebase for known vulnerabilities using `govulncheck` via the `make vuln` target. It also provides guidance on fixing vulnerable dependencies by upgrading them with `go get` according to semver.

## Usage

### Scan for Vulnerabilities

```bash
make tools
make deps
make vuln
```

### Fix Vulnerable Dependencies

When a vulnerability is found in a dependency, update it using:

```bash
go get -u <module>@latest
```

Or to update to a specific version that fixes the issue (respecting semver):

```bash
go get <module>@<fixed_version>
```

Then run `make deps` to synchronize the module changes.

## Workflow

1. Ensure required tools are available (`make tools`)
2. Ensure dependencies are downloaded (`make deps`)
3. Run vulnerability scan (`make vuln`)
4. Identify vulnerable modules from the report
5. Check the module's release history for the minimum version that fixes the vulnerability
6. Update the module using `go get` with the appropriate version
7. Run `make deps` to update `go.mod` and `go.sum`
8. Re-run `make vuln` to verify the vulnerability is resolved

## Requirements

- `govulncheck` must be installed (`go install golang.org/x/vuln/cmd/govulncheck@latest`)
- Go 1.26+
- Internet access to fetch vulnerability database and module updates

## Notes

- Always verify that updating a dependency does not break existing functionality
- Consider running tests (`make test`) after updating dependencies
- For production applications, prefer pinning to a specific patch version over `@latest`
