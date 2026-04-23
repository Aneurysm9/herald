# Changelog

## [0.3.1] — 2026-04-23

### Bug Fixes

- Lazy-init DNS resolver so Nix sandbox builds succeed([f268383](https://github.com/Aneurysm9/herald/commit/f26838396f666807bf35c3054136fe863ad7d4b7))

- Pass listZone=true when listing zone records([71f5877](https://github.com/Aneurysm9/herald/commit/71f58773703115702beb908d72e9aef136e50274))

- Pass VERSION into release-hashes commit step env([b82a8bc](https://github.com/Aneurysm9/herald/commit/b82a8bc9b4f37a83df7da357bc86df0769a66618))

## [0.3.0] — 2026-04-19

### Features

- Support multiple mirror providers with richer transforms([f2e0419](https://github.com/Aneurysm9/herald/commit/f2e04199e4cd8c61d83691c6cbacc638b9b89cc0)) **BREAKING**

- Add per-client rate limiting on API and DNS UPDATE endpoints (#22)([8a19011](https://github.com/Aneurysm9/herald/commit/8a1901129c70238d190468487199b0d2b3daa8cf))

- Add in-process integration tests (#21)([21d5ffe](https://github.com/Aneurysm9/herald/commit/21d5ffe038b3d1e480e0afc35df24aecee7938b4))

- Add config validation at startup (#19)([5750bef](https://github.com/Aneurysm9/herald/commit/5750befd08d8b8c3468eeb715ea9c02c5ac6e5d4))

- Targeted per-name prerequisite queries([e9b3160](https://github.com/Aneurysm9/herald/commit/e9b31603e4ceb7c790c68280fb8744b9a09338de))

- Add prerequisite support and self-healing state resync([5cb047b](https://github.com/Aneurysm9/herald/commit/5cb047bec90d875e8e26e9586b5f1296d140b8b8))

- Wire metrics, add spans, fix DNS UPDATE log levels([6860fa1](https://github.com/Aneurysm9/herald/commit/6860fa18e59a04212937de5d61e799040c42eccc))


### Bug Fixes

- Persist to SQLite before updating in-memory state (#18)([017c03f](https://github.com/Aneurysm9/herald/commit/017c03f006a08206f40f1e57dbe80fec8cc80df9))

- Use workflow_run trigger for release hash updates([6d5eda3](https://github.com/Aneurysm9/herald/commit/6d5eda31dd8aad71a3e5efe2cd031fdaa3b81460))


### Refactoring

- Split dns_server.rs into focused submodules (#20)([3416825](https://github.com/Aneurysm9/herald/commit/3416825633bc05bac54ddd839c9f7788b9e87beb))

- Clean up module namespace and eliminate redundant types([9289fd8](https://github.com/Aneurysm9/herald/commit/9289fd8205445aea255f250f4559d548d15511e1))

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

