# Phase 5A verification service contract

## Scope

Phase 5A provides a read-only, UI-independent verification engine. It performs
exact lookup and produces a structured technical conclusion. It does not grant
access to records or decide which result fields a caller may display.

Project and administrator UIs must enforce their own REDCap authorization and
data-access-group rules before invoking verification or exposing its result.

## Input

The service accepts:

- the complete capture reference printed in the watermark, in canonical WM1
  form (`S-XXXX-XXXX-XXXX-X`); and
- either a positive project ID for project-scoped lookup or `null` for a global
  administrator lookup.

Malformed references are rejected before any log query. Lookup is always exact;
there is no prefix, wildcard, or browse operation. A project-scoped lookup adds
an explicit project restriction to the log query. Duplicate upload events for a
capture reference, or duplicate upload/binding events for an edoc, are treated
as log-integrity failures rather than silently selecting one.

## Result structure

The service returns:

- `status`: the primary UI-independent conclusion;
- `binding_state`: `unknown`, `unbound`, or `bound`;
- `integrity`: `not_checked`, `valid`, `invalid`, or `incomplete`;
- `current_state`: `unknown`, `current`, or `historical`;
- the matched upload and binding payloads;
- non-content edoc metadata;
- individual nullable checks; and
- stable machine-readable issue codes.

Primary statuses are:

- `invalid_reference`: the input is not a complete canonical capture reference;
- `unknown`: no upload exists in the requested scope;
- `unbound`: upload provenance exists but no successful binding exists;
- `invalid`: a cryptographic or stored relationship check failed;
- `incomplete`: required edoc or current-field information is unavailable;
- `valid_current`: all checks pass and the field still contains the edoc; and
- `valid_historical`: all checks pass but the field no longer contains it.

The independent checks are:

- binding MAC validation;
- upload-to-binding relationship validation;
- stable-scope anchor recomputation;
- edoc existence;
- final edoc SHA-256 comparison; and
- current-field comparison.

An unbound result remains `unbound` even if a provenance/file check reports an
issue; callers must also inspect `integrity`, `checks`, and `issues`.

## Verification flow

1. Validate the full capture-reference format.
2. Look up exactly one `sigwm_upload` in the requested project scope.
3. Recompute the anchor from the upload's watermark version, project, event,
   instrument, and field.
4. Confirm that the log-row project and payload project agree.
5. Read the edoc through REDCap's `Files` storage abstraction, which supports
   local and configured external storage backends.
6. Recompute SHA-256 over the current edoc bytes without returning those bytes
   in the result.
7. Look up the one-time binding by edoc ID.
8. Validate its MAC and its immutable relationship to upload provenance.
9. Only after the binding is trusted, read the bound REDCap field and compare
   its current edoc value.

The current-value adapter handles classic event data, repeating instruments,
and repeating events using the normalized repeat data stored in the binding.

## Security and privacy boundary

The service may return record IDs and username snapshots because later callers
need them to render authorized technical results. Project-facing code must
redact or withhold them when REDCap rights or DAG membership do not permit
display.

No signature bytes, base64 content, survey hashes, or survey bearer credentials
are returned or logged by verification. File-read failures produce structured
incomplete results rather than exposing storage paths or exception details.

## Project page adapter (Phase 5B)

The authenticated project page is registered in `config.json` and submits the
capture reference by POST with REDCap's CSRF token, keeping the identifier out
of the page URL and ordinary browser history. The module link is available to a
superuser or a project user who has at least read-only viewing access to one
instrument containing an enabled signature field.

The image prints the reference as `S:XXXX-XXXX-XXXX-X`, while the log's
canonical internal form is `S-XXXX-XXXX-XXXX-X`. The page displays `S:` as a
fixed input-group prefix so the user enters exactly the suffix visible on the
image. The controller normalizes that suffix to the canonical form; pasted
`S:...` and `S-...` values are accepted as conveniences as well.

Authorization is performed before full verification reads an edoc or current
record value:

1. Exact project-scoped upload lookup establishes the project and instrument.
2. The user must have form-level viewing access to that instrument.
3. A binding must have a valid MAC before its record ID is trusted for access
   control.
4. A DAG-restricted user may view the result only when the bound record belongs
   to that same DAG.

An unbound upload has no authoritative record or DAG. It is therefore available
on the project page only to superusers and users with project-wide record scope;
DAG-restricted users receive the same generic unavailable response used for
out-of-scope results.

The project controller transforms the backend result into an allowlisted view
model. It may expose authorized record and actor details, verification checks,
and non-content edoc metadata. It never forwards raw upload/binding payloads,
envelope nonces, binding MACs, log IDs, file bytes, or exception details.

## Administrator page adapter (Phase 5C)

The Control Center page is available only to REDCap superusers. Its link-display
hook and controller factory both enforce that requirement, so direct page access
uses the same authorization boundary as menu visibility.

The page is an exact global lookup only. It accepts either a capture-reference
suffix (normalized to `S-...`) or a positive numeric edoc ID by CSRF-protected
POST. An edoc lookup first resolves the globally unique `sigwm_upload` event,
then invokes the service with that event's capture reference and a `null`
project scope. It has no listing, prefix search, or browse endpoint.

The administrator view may expose the upload and binding project/log IDs and a
technical history for the resolved edoc. It allowlists the ordinary log columns
needed for diagnosis (event type, timestamp, actor, project, record, scope and
origin fields, and technical message). It does not expose raw `payload_json`,
envelope nonces, binding MAC values, file bytes, or exception text. Each
history event uses a vertical layout; its remaining allowlisted fields appear
as pretty-printed JSON. Clearing both search controls removes only the rendered
result from the DOM without a navigation or repeat submission.
