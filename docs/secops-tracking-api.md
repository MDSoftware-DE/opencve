# SecOps tracking API

This fork adds an authenticated write-back endpoint for external security
orchestration. It updates the existing project CVE tracker, adds a visible
comment, and records an immutable idempotency event in one transaction.

## Endpoint

```text
GET|PATCH /api/v2/organizations/{organization}/projects/{project}/cves/{cve_id}/tracking
```

The request uses an organization token:

```http
Authorization: Bearer opc_org.<token-id>.<secret>
Content-Type: application/json
```

The organization token must belong to the organization in the URL and must
have an attributable `created_by` user. The project must subscribe to a
vendor or product affected by the CVE.

## Write a tracking event

```json
{
  "event_id": "ops-triage:CVE-2026-1001:github:42:resolved:v1",
  "status": "resolved",
  "comment": "SecOps status: resolved. Authoritative case: https://github.com/MDSoftware-DE/vps-colossus-config/issues/42",
  "case_url": "https://github.com/MDSoftware-DE/vps-colossus-config/issues/42"
}
```

`status` accepts the same values as the OpenCVE project tracker.
`case_url` is restricted to HTTPS issue URLs below
`github.com/MDSoftware-DE`. Comments render recognized URLs as safe,
clickable links in the tracking history.

A first write returns `created: true`. Replaying the identical
`event_id` and payload returns `created: false` without creating another
tracker event or comment. Reusing an `event_id` with a different payload
returns HTTP 409.

```json
{
  "cve_id": "CVE-2026-1001",
  "status": "resolved",
  "case_url": "https://github.com/MDSoftware-DE/vps-colossus-config/issues/42",
  "event_id": "ops-triage:CVE-2026-1001:github:42:resolved:v1",
  "created": true
}
```

## Read current state and history

A GET request returns the current project tracker status and the latest 100
idempotency events. Secrets and comment bodies are not returned by this
endpoint.
