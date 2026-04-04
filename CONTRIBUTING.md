# Contributing to Herald

Thank you for your interest in contributing to Herald! This guide covers development setup, code style, testing practices, and the contribution workflow.

## Development Setup

Herald uses Nix for reproducible development environments. The flake provides all necessary dependencies.

### Prerequisites

- [Nix](https://nixos.org/download.html) with flakes enabled
- Git

### Getting Started

```bash
# Clone the repository
git clone https://github.com/Aneurysm9/herald.git
cd herald

# Enter the development shell (provides Rust toolchain, cargo-watch, alejandra)
nix develop

# Build the project
cargo build

# Run tests
cargo test

# Run with file watching (auto-recompile on changes)
cargo watch -x run
```

### Development Tools

The Nix dev shell provides:
- **Rust toolchain** — stable rustc, cargo, clippy, rustfmt
- **cargo-watch** — automatic recompilation on file changes
- **alejandra** — Nix code formatter

## Code Style

Herald enforces strict code quality standards via `clippy::pedantic` and rustfmt.

### Clippy Pedantic

All code must pass `cargo clippy --all-targets -- -D warnings` cleanly. The `clippy::pedantic` lint group is enabled project-wide via `[lints.clippy]` in `Cargo.toml`.

**Rules**:
- **Maintain pedantic compliance** — fix warnings rather than suppressing them
- **Targeted `#[allow(...)]` only when justified** — add a comment explaining why
  ```rust
  #[allow(clippy::unused_async)] // Will await once DNS queries are implemented
  async fn poll_dns(&self) -> Result<Vec<SourceRecord>> {
      // TODO: Implement raw DNS zone transfer
      Ok(Vec::new())
  }
  ```
- **Never blanket-allow pedantic** — do not add `#![allow(clippy::pedantic)]` to any module
- **New lint exceptions require a code comment** explaining the rationale

### Formatting

Use `rustfmt` with the default configuration:

```bash
# Format all code
cargo fmt

# Check formatting without modifying
cargo fmt -- --check
```

### Error Handling

- **`anyhow::Result`** for application errors (main, API handlers, reconciliation)
- **`thiserror`** for library-style errors in provider/backend traits (if needed)
- **Prefer explicit error handling over `.unwrap()`** — use `.context()` to add meaningful error messages
  ```rust
  tokio::fs::read_to_string(&path)
      .await
      .context("reading Cloudflare token file")?
  ```

### Logging

Use `tracing` for structured logging with relevant context fields:

```rust
tracing::info!(
    provider = provider.name(),
    count = records.len(),
    "collected records"
);

tracing::error!(
    error = %e,
    zone = %zone_name,
    "failed to lookup zone ID"
);
```

**Guidelines**:
- Use `info` for normal operations, `warn` for recoverable issues, `error` for failures
- Include relevant context as structured fields (not in the message string)
- Keep messages concise and actionable

### Async Traits

Use `async_trait` for async trait methods:

```rust
use async_trait::async_trait;

#[async_trait]
impl Provider for MyProvider {
    async fn records(&self) -> Result<Vec<DnsRecord>> {
        // implementation
    }
}
```

### Documentation

All public items should have rustdoc comments:

```rust
/// Polls the source DNS server and updates cached records.
///
/// This runs on a schedule (configured via `mirror.interval`) and:
/// 1. Fetches all records from the source
/// 2. Applies transformation rules
/// 3. Updates the internal cache
pub async fn poll(&self) -> Result<()> {
    // implementation
}
```

## Testing

Herald uses a mix of unit tests, integration tests, and mocked external services.

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific module
cargo test provider::acme

# Run tests with output
cargo test -- --nocapture

# Run a single test
cargo test test_set_challenge_success
```

### Unit Tests

Unit tests live in `#[cfg(test)] mod tests { }` blocks within source files. Use them for:
- Provider logic (e.g., name transformation, glob matching, rule application)
- Reconciler diff logic
- Config parsing

Example:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_name() {
        assert_eq!(
            transform_name("host.internal.example.org", "internal.example.org", "example.com"),
            Some("host.example.com".to_string())
        );
    }
}
```

### Integration Tests

Integration tests use real dependencies where practical:
- **axum-test** for API endpoint tests
- **wiremock** for mocking external HTTP APIs (Cloudflare, Technitium)

#### Testing API Endpoints

Use `axum-test` (v17+ for axum 0.8 compatibility):

```rust
use axum_test::TestServer;

#[tokio::test]
async fn test_health() {
    let state = test_state();
    let app = router(state);
    let server = TestServer::new(app.into_make_service()).unwrap();

    let response = server.get("/health").await;
    response.assert_status_ok();
    response.assert_text("ok");
}
```

#### Mocking Backend APIs

Use `wiremock` for Cloudflare/Technitium API interactions:

```rust
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path, bearer_token};

#[tokio::test]
async fn test_cloudflare_create() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/zones/zone-123/dns_records"))
        .and(bearer_token("test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(cf_success_response()))
        .expect(1)
        .mount(&server)
        .await;

    // Test code that calls the Cloudflare API
}
```

### Test Coverage Goals

- All public provider methods should have unit tests
- All API endpoints should have integration tests
- All reconciler logic paths (create/update/delete) should be covered
- Error cases should be tested (permission denied, API failures, etc.)

## Adding a Provider

Providers contribute records to the desired state set. To add a new provider:

### 1. Define the Provider Module

Create `src/provider/my_provider.rs`:

```rust
use super::{DnsRecord, Provider};
use anyhow::Result;
use async_trait::async_trait;

/// Provider that fetches records from MySource.
pub struct MyProvider {
    config: MyProviderConfig,
}

impl MyProvider {
    pub fn new(config: MyProviderConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Provider for MyProvider {
    fn name(&self) -> &'static str {
        "my_provider"
    }

    async fn records(&self) -> Result<Vec<DnsRecord>> {
        // Fetch and return records
        Ok(vec![])
    }
}
```

### 2. Add Config Types

In `src/config.rs`:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct MyProviderConfig {
    pub api_url: String,
    pub token_file: String,
}
```

Add to `ProvidersConfig`:

```rust
#[derive(Debug, Default, Deserialize)]
pub struct ProvidersConfig {
    #[serde(default)]
    pub r#static: Option<StaticProviderConfig>,
    // ...
    #[serde(default)]
    pub my_provider: Option<MyProviderConfig>,
}
```

### 3. Register in main.rs

In `src/main.rs`, initialize the provider:

```rust
if let Some(ref my_config) = config.providers.my_provider {
    let p = Arc::new(MyProvider::new(my_config.clone()));
    tracing::info!("my_provider loaded");
    providers.push(p);
}
```

### 4. Write Tests

Add tests in `src/provider/my_provider.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_my_provider() {
        let config = MyProviderConfig {
            api_url: "http://localhost".to_string(),
            token_file: "/tmp/token".to_string(),
        };
        let provider = MyProvider::new(config);
        // Test the provider
    }
}
```

## Adding a Backend

Backends apply changes to a DNS provider (Cloudflare, Route53, etc.). To add a new backend:

### 1. Define the Backend Module

Create `src/backend/my_backend.rs`:

```rust
use super::{Backend, Change, ExistingRecord};
use anyhow::Result;
use async_trait::async_trait;

pub struct MyBackend {
    api_url: String,
    token: String,
}

impl MyBackend {
    pub async fn new(config: &MyBackendConfig) -> Result<Self> {
        // Initialize backend
        Ok(Self {
            api_url: config.api_url.clone(),
            token: load_token(&config.token_file).await?,
        })
    }
}

#[async_trait]
impl Backend for MyBackend {
    fn name(&self) -> &'static str {
        "my_backend"
    }

    async fn get_records(&self) -> Result<Vec<ExistingRecord>> {
        // Fetch existing records from backend
        Ok(vec![])
    }

    async fn apply_change(&self, change: &Change) -> Result<()> {
        match change {
            Change::Create(record) => {
                // Create record at backend
            }
            Change::Update { id, new, .. } => {
                // Update record at backend
            }
            Change::Delete(existing) => {
                // Delete record from backend
            }
        }
        Ok(())
    }
}
```

### 2. Add to Backend Config

In `src/config.rs`:

```rust
#[derive(Debug, Default, Deserialize)]
pub struct BackendsConfig {
    #[serde(default)]
    pub cloudflare: Option<CloudflareConfig>,
    #[serde(default)]
    pub my_backend: Option<MyBackendConfig>,
}
```

### 3. Update main.rs

Choose which backend to use (currently only one backend is supported):

```rust
let backend: Arc<dyn Backend> = if let Some(ref cf_config) = config.backends.cloudflare {
    Arc::new(CloudflareBackend::new(cf_config).await?)
} else if let Some(ref my_config) = config.backends.my_backend {
    Arc::new(MyBackend::new(my_config).await?)
} else {
    anyhow::bail!("no backend configured");
};
```

## Commit Messages

Use conventional commits format for clear, structured commit history:

```
<type>: <description>

[optional body]

[optional footer]
```

**Types**:
- `feat:` — new feature
- `fix:` — bug fix
- `test:` — adding or updating tests
- `docs:` — documentation changes
- `refactor:` — code refactoring without behavior change
- `chore:` — maintenance tasks (dependencies, CI, tooling)

**Examples**:

```
feat: add Route53 backend support

Implements the Backend trait for AWS Route53, supporting hosted zones
and record sets via the AWS SDK.
```

```
fix: handle empty mirror poll responses gracefully

Previously, an empty Technitium API response would cause a panic. Now
returns an empty record set and logs a warning.
```

```
test: add wiremock integration tests for Cloudflare backend

Covers all Change types (create, update, delete) and API error handling.
```

**Signing commits**:
- All commits should be signed off (`git commit -s`)
- This adds `Signed-off-by: Your Name <email>` to the commit message
- Per the project memory, always use the `-s` flag

## Pull Requests

### Before Submitting

Ensure your PR passes all checks:

```bash
# Format code
cargo fmt

# Run clippy
cargo clippy --all-targets -- -D warnings

# Run tests
cargo test

# Build the project
cargo build
```

### PR Description

Include in your PR description:
- **What** — what does this PR change?
- **Why** — why is this change needed?
- **How** — how does it work (for non-trivial changes)?
- **Testing** — what tests were added or updated?

**Example**:

```markdown
## Summary

Adds support for DNS mirroring from Technitium DNS Server.

## Changes

- New `MirrorProvider` that polls Technitium API on a configurable interval
- Name transformation rules (suffix replacement, glob matching)
- Config schema for `providers.mirror`

## Testing

- Unit tests for `transform_name`, `glob_match`, `apply_rules`
- Integration test with wiremock mocking Technitium API responses

## Notes

The `poll_dns` method is stubbed for future raw DNS zone transfer support.
```

### CI Checks

The Nix flake CI enforces:
- `cargo clippy --all-targets -- --deny warnings`
- `cargo test`
- `cargo build`
- `nix build` (static binary)

All checks must pass before merging.

### Review Process

- PRs require review from a maintainer
- Address feedback by pushing new commits (do not force-push during review)
- Once approved, the PR will be squash-merged to main

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for design questions
- Reach out to maintainers for contribution guidance

Thank you for contributing to Herald!
