# AGENTS.md

## Project Overview
Hackathon project written in **Go (Golang)**. Each teammate owns a specific part of the problem statement and works on an isolated feature branch.

## Language & Stack
- **Language:** Go (Golang)
- **Go Version:** `go1.27.0-X:nodwarf5 linux/amd64`
  - Verify with: `go version`
  - Expected output: `go version go1.27.0-X:nodwarf5 linux/amd64` (or similar, the version should match)
- Follow idiomatic Go conventions (`gofmt`, `go vet`, effective Go style).
- Use modules (`go.mod` / `go.sum`) for dependency management.

## Branching Rules
- **Never commit directly to `main`.**
- Every teammate works on a dedicated feature branch.
- Branch names must reflect the specific part of the problem statement being worked on.
- Use the `feature/<name>` naming convention, for example:
  - `feature/a`
  - `feature/b`
  - `feature/<your-feature-name>`

## Repository Structure
.
├── utils/ # Utility code (helpers, shared functions) — lives at project root
├── src/ # Feature code — lives at project root
├── go.mod
├── go.sum
└── AGENTS.md

### Placement Rules
- **Utility code** → goes into `utils` files at the **project root**.
- **Feature code** → goes into the `src` folder at the **project root**.

## Workflow
1. Pull the latest `main` before starting: `git checkout main && git pull`.
2. Create your feature branch: `git checkout -b feature/<your-feature>`.
3. Do your work in `src/` (features) or `utils/` (utilities).
4. Run `gofmt`, `go vet`, and `go test ./...` before committing.
5. Push your branch and open a pull request against `main`.
6. Do **not** merge your own PR — request a teammate's review.

## Do Not
- ❌ Commit or push directly to `main`.
- ❌ Put utility code inside `src/`.
- ❌ Put feature code inside `utils/`.
- ❌ Use vague branch names (e.g., `fix`, `test`, `mybranch`) — branch names must reflect the feature.

## Quick Reference
| Action | Command |
|---|---|
| New feature branch | `git checkout -b feature/<name>` |
| Format code | `gofmt -w .` |
| Vet code | `go vet ./...` |
| Run tests | `go test ./...` |
| Build | `go build ./...` |
