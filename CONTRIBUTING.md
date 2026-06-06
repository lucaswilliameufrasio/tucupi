# Contributing to Tucupi

First off, thank you for considering contributing! We welcome all kinds of contributions, not just code.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Branch Naming Convention](#branch-naming-convention)
- [Commit Convention](#commit-convention)
- [Pull Request Process](#pull-request-process)
- [Testing](#testing)
- [AI-Generated Contributions](#ai-generated-contributions)
- [Release Process](#release-process)

## Code of Conduct

This project follows a simple principle: be respectful and constructive. We do not tolerate harassment, discrimination, or any form of toxic behaviour.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/tucupi.git`
3. Build: `cargo build`
4. Run tests: `cargo test`

## Development Workflow

1. Pick an issue to work on (or create one)
2. Create a branch following the naming convention
3. Make your changes
4. Ensure `cargo fmt --all --check` passes
5. Ensure `cargo clippy --all-targets --all-features -- -D warnings` passes
6. Ensure `cargo test --all-targets` passes
7. Update `CHANGELOG.md` if your change is user-facing
8. Open a Pull Request

## Branch Naming Convention

Branches should follow the pattern:

```
<type>/<description>
```

Types:

| Type       | Purpose                                 |
|------------|-----------------------------------------|
| `feat/`    | New feature                             |
| `fix/`     | Bug fix                                 |
| `docs/`    | Documentation changes                   |
| `refactor/`| Code refactoring                        |
| `perf/`    | Performance improvements                |
| `test/`    | Adding or updating tests                |
| `ci/`      | CI/CD changes                           |
| `chore/`   | Maintenance, dependencies, config       |
| `security/`| Security fixes                          |

Examples:
- `feat/php-ruby-python-adapters`
- `fix/build-metadata-comparison`
- `docs/architecture-readme`

## Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `ci`, `chore`

Examples:
```
feat(adapters): add PHP, Ruby, Python ecosystem support
fix(cargo): strip build metadata from version comparison
docs(readme): add examples section
chore(deps): update ratatui to 0.30.0
```

## Pull Request Process

1. Ensure your branch is up to date with `main`
2. Run all checks locally (`fmt`, `clippy`, `test`)
3. Update `CHANGELOG.md` under the `[Unreleased]` section
4. Open a PR with a clear description
5. Link any related issues
6. Wait for review

### PR Checklist

- [ ] Code follows the project's style
- [ ] `cargo fmt` passes
- [ ] `cargo clippy` passes with no warnings
- [ ] `cargo test` passes
- [ ] Documentation updated if needed
- [ ] CHANGELOG updated if user-facing change

## Testing

- Unit tests: `cargo test --lib`
- Integration tests: `cargo test --test *`
- All tests: `cargo test --all-targets`

When adding new adapters, include at least one integration test.

## AI-Generated Contributions

Contributions generated or assisted by AI tools (such as code completion or agents) are welcome, provided that:

1. The contributor takes full responsibility for the code
2. The code is properly reviewed and tested
3. The contributor understands the code they are submitting
4. AI tools are not used to generate low-quality or spam contributions

## Release Process

Releases are automated via `prepare-release.yml` workflow:

1. A maintainer triggers `prepare-release.yml`
2. It creates a PR with version bump and changelog updates
3. After review and merge, `release.yml` builds and publishes to crates.io
