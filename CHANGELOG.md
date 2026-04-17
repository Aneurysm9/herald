# Changelog

## [0.2.0] — 2026-04-17

### Features

- Add RFC 2136 DNS UPDATE support via hickory-dns([beb476f](https://github.com/Aneurysm9/herald/commit/beb476fa5e9b7269d243832d5ef82468b5735cb6))

- Expose pre-built release binaries as flake packages([e539c21](https://github.com/Aneurysm9/herald/commit/e539c216fc5945a527760f643b09a841366031be))


### Bug Fixes

- Replace .expect() with error propagation in provider init([50c1a11](https://github.com/Aneurysm9/herald/commit/50c1a1141eee5cf0303652a890f29ec39d366c08))

- Use system CA roots for TLS instead of bundled Mozilla roots([6435be7](https://github.com/Aneurysm9/herald/commit/6435be7f1eb14d004e88a6bdc10f7321dcf81d35))

## [0.1.3] — 2026-04-04

### Bug Fixes

- Update aws-lc-sys to 0.39.1 (RUSTSEC-2026-0044, RUSTSEC-2026-0048)([c2c4ebf](https://github.com/Aneurysm9/herald/commit/c2c4ebfc02f67fd7c83c4c230f182a6b21854c4d))


### Refactoring

- Migrate from rustls-pemfile to rustls-pki-types (RUSTSEC-2025-0134)([f85dfac](https://github.com/Aneurysm9/herald/commit/f85dfac612361552d66e52f13cb76285bdf88e39))

## [0.1.2] — 2026-04-04

### Bug Fixes

- Skip tests for cross-compiled static binaries([d362e9f](https://github.com/Aneurysm9/herald/commit/d362e9f21407ec237d896de8f52924cb99587ef2))

## [0.1.1] — 2026-04-04

### Features

- Add aarch64 static binary build and fix musl cross-compilation([7cecbdc](https://github.com/Aneurysm9/herald/commit/7cecbdc7ad3ca02e6b5159e284996bd9b7b403ca))


### Bug Fixes

- Use musl cross-compiler for static binary build([b150917](https://github.com/Aneurysm9/herald/commit/b1509175248fccfd6c57e206940a8db26fa37f6e))

## [0.1.0] — 2026-04-04

### Features

- Herald v0.1.0 — DNS control plane for multi-provider record management([a1ba013](https://github.com/Aneurysm9/herald/commit/a1ba013472f988c263b5a47d7d21aabac3208fcb))

