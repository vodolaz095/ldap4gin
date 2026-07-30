# lint

Use when the user needs to run linting on the Go codebase and automatically fix any issues found.

## Usage

1. Verify required tools are available (go, gopls, staticcheck)
2. Run `make lint` to identify issues
3. Analyze lint output and apply fixes
4. Verify fixes resolved all issues

## Implementation

The skill should:
- Check for required tools before running
- Execute `make lint` command
- Parse lint output to identify issues
- Apply fixes using appropriate methods (edit, lsp_replace_symbol, etc)
- Re-run linting to verify fixes
- Handle different types of lint issues appropriately

## Requirements

- Must verify go, gopls, and staticcheck are available before running
- Must run `make lint` as the primary lint command
- Must attempt to fix all reported issues
- Must verify fixes by re-running lint
- Should preserve code functionality while improving style

## Dependencies

- Go compiler (go)
- Go language server (gopls)
- Staticcheck tool
- Make build system
- Access to project files