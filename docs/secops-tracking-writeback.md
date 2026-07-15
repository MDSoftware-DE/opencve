# SecOps tracking writeback

This extension synchronizes the current SecOps case state into an OpenCVE
project CVE. The authoritative case remains the GitHub issue in
`MDSoftware-DE/vps-colossus-config`; OpenCVE is the project-specific status and
history view.

## Authentication and route

Use an active OpenCVE organization API token:

```http
Authorization: Bearer opc_org.<token-id>.<secret>
```

The token organization must match the nested organization in the URL. PATCH
uses the token's `created_by` user as the immutable audit author. Request data
cannot select another author.

```http
GET   /api/organizations/{organization}/projects/{project}/cve/{cve_id}/tracking
PATCH /api/organizations/{organization}/projects/{project}/cve/{cve_id}/tracking
```

The project must subscribe to a vendor or product associated with the CVE.
Unknown organizations, projects, CVEs, cross-organization tokens, and
unsubscribed CVEs return no tracking resource.

## Read response

Before the first SecOps writeback:

```json
{
  "cve_id": "CVE-2026-1234",
  "status": null,
  "case_url": null,
  "event_id": null
}
```

After a writeback, `status` is the current tracker state and `case_url` plus
`event_id` identify the latest immutable event.

## Write request

```json
{
  "event_id": "ops-triage:CVE-2026-1234:github:42:resolved:v1",
  "status": "resolved",
  "comment": "SecOps-Fall abgeschlossen: https://github.com/MDSoftware-DE/vps-colossus-config/issues/42",
  "case_url": "https://github.com/MDSoftware-DE/vps-colossus-config/issues/42"
}
```

Allowed statuses:

- `to_evaluate`
- `pending_review`
- `analysis_in_progress`
- `remediation_in_progress`
- `evaluated`
- `resolved`
- `not_applicable`
- `risk_accepted`

Validation limits:

- `event_id`: required, trimmed, at most 128 characters.
- `comment`: required, trimmed, at most 4096 characters.
- `case_url`: HTTPS only, exact host `github.com`, owner
  `MDSoftware-DE`, and an `/issues/{positive-number}` path.
- URL credentials, ports, queries, fragments, other owners, pull requests, and
  non-issue paths are rejected.

A first write returns `created: true`. Repeating the same normalized payload
with the same `event_id` is a successful no-op with `created: false`.
Reusing an `event_id` with a different semantic payload returns HTTP 409 and
does not change the tracker, comment, or event ledger.

Status, comment, and event are written in one database transaction. The project
and tracker boundary is locked during the write, and the database also enforces
uniqueness across `project + cve + event_id`.

## Example

```bash
curl --fail-with-body \
  --request PATCH \
  --header "Authorization: Bearer ${OPENCVE_ORG_TOKEN}" \
  --header "Content-Type: application/json" \
  --data '{
    "event_id": "ops-triage:CVE-2026-1234:github:42:resolved:v1",
    "status": "resolved",
    "comment": "SecOps-Fall abgeschlossen: https://github.com/MDSoftware-DE/vps-colossus-config/issues/42",
    "case_url": "https://github.com/MDSoftware-DE/vps-colossus-config/issues/42"
  }' \
  "https://opencve.example/api/organizations/example/projects/example/cve/CVE-2026-1234/tracking"
```

Never put an organization token in source control, issue text, shell history, or
logs.

## User interface

Tracking comments pass through Django's escaping, `urlize`, and line-break
filters. The central HTTPS GitHub issue is clickable while HTML, script tags,
attributes, and `javascript:` text remain escaped or non-clickable.

## Production artifact

The GitHub-hosted `Release OpenCVE web image` workflow builds the web image
from the exact checked-out commit. Pull requests build and test both image
stages without publishing. A push to `release/md-secops-v3.0.0` publishes only
`ghcr.io/mdsoftware-de/opencve-web:sha-<full-commit>` and records the immutable
registry digest in the workflow summary. No `latest` tag is produced.

Production must pin `ghcr.io/mdsoftware-de/opencve-web:<digest>`, not the
branch or SHA tag. The test stage applies all migrations and executes the SecOps
API and UI contract tests against PostgreSQL before publication.

## Upgrade

1. Back up the OpenCVE PostgreSQL database and verify the backup artifact.
2. Deploy an immutable reviewed application image.
3. Review the migration plan.
4. Apply `projects.0011_cvetrackerevent`.
5. Run an authenticated GET.
6. PATCH one non-production test project CVE twice with the same event ID.
7. Verify one comment, one event, and `created: false` on the retry.
8. Verify the rendered OpenCVE tracking history contains the clickable case
   link.

The migration creates `opencve_cve_tracker_events`, its unique constraint, and
lookup indexes. It does not alter or delete existing tracker or comment rows.

## Rollback

On application failure, restore the previous application image and stop serving
the tracking route. Keep migration `0011`, event rows, and comments in place;
they are forward-compatible audit evidence. Do not reverse the migration or
delete synchronized history during an application rollback.

Disable the external writer before rollback if it cannot receive successful
acknowledgements. Re-enable it only after GET, PATCH idempotency, database
counts, and UI rendering are verified again.
