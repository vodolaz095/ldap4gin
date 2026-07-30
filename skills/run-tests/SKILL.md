# SKILL.md

## Run Unit Tests

This skill allows you to run unit tests for the project using the Makefile.

### Usage

To run the unit tests, use the following command:

```bash
make test
```

This will execute `go test -v ./...` which runs all tests in the project with verbose output.

### Additional Testing Options

- `make cover`: Run tests with coverage reporting
- `make check`: Run linting before tests

### Prerequisites

Ensure that you have the required tools installed:

```bash
make tools
```

This checks for the presence of `go`, `golint`, and `govulncheck`.

### Dependencies

Make sure all dependencies are downloaded:

```bash
make deps
```

This runs `go mod download`, `go mod verify`, and `go mod tidy`.

---

💘 Generated with Crush
