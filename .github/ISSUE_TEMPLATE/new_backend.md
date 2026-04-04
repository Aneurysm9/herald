---
name: New Backend
about: Propose support for a new DNS backend
labels: enhancement, backend
---

## Backend Name

Name of the DNS provider or server (e.g., Route53, PowerDNS, Hetzner DNS).

## API Documentation

Link to the backend's API documentation.

## Authentication Method

How does the API authenticate? (e.g., API token, IAM role, basic auth)

## Record Operations

Which operations does the API support?

- [ ] List records (with pagination?)
- [ ] Create record
- [ ] Update record
- [ ] Delete record

## Managed Record Tracking

Does the API support a comment or tag field on records? Herald uses this to distinguish managed records from manually-created ones (tagged with `managed-by: herald`).

## Multi-Zone Support

Does the API support managing multiple zones with a single credential?

## Willingness to Implement

- [ ] I'm willing to implement this backend
- [ ] I'd like someone else to implement it
- [ ] I can help test but not implement

## Additional Context

Any other relevant information (rate limits, special considerations, etc.).
