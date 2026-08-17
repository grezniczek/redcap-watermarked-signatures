# Phase 5A verification service contract

## Scope

Phase 5A provides a read-only, UI-independent verification engine. It performs
exact lookup and produces a structured technical conclusion. It does not grant
access to records or decide which result fields a caller may display.

Project and administrator UIs must enforce their own REDCap authorization and
data-access-group rules before invoking verification or exposing its result.

## Input

The service accepts:

- the complete capture reference printed in the watermark, in canonical
  `S:XXXX-XXXX-XXXX-X` form; and
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
- `current_record_id`: the record's currently valid ID, when a binding exists;
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
- binding-extension MAC validation for format-v2 bindings;
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
8. Validate its base MAC, required format-v2 extension MAC, and immutable
   relationship to upload provenance.
9. Only after the binding is trusted, read the bound REDCap field at the current
   record ID and compare its current edoc value.

## Binding-format compatibility

The upload/binding provenance version is independent of `WM1` and the signed
envelope version. Format v2 preserves the released v1 `binding_mac` payload so
that a v1.0.2 verifier can still validate a v2 binding's base MAC and matched
upload/binding relationship. It authenticates `field_reference` using a
separately derived extension MAC over the provenance version, base MAC, and
field reference. Current verification requires that extension MAC for v2;
legacy v1 bindings remain valid without one.

Future authenticated binding extensions must preserve the prior base-MAC
schema, bind their extension MAC to the protected base MAC, and include a
regression test of the previous verifier's base-MAC behavior.

The current-value adapter handles classic event data, repeating instruments,
and repeating events using the normalized repeat data stored in the binding.
The binding payload's `record_id` is the immutable binding-time value; REDCap's
indexed External Module log `record` value supplies `current_record_id` after
record rename. The MAC therefore remains verifiable while the live lookup and
authorized display track the record's current identity.

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

The image, signed envelope, log payloads, and details pages use the same
canonical identifiers: `S:`, `C:`, and `A:`. Upload provenance may additionally
contain an optional `field_reference`, which is shown as an authorized detail
but is not used for lookup. The page displays `S:` as a fixed input-group prefix
so the user enters exactly the suffix visible on the image; the controller
restores the canonical `S:` prefix before exact lookup.

Authorization is performed before full verification reads an edoc or current
record value:

1. Exact project-scoped upload lookup establishes the project and instrument.
2. The user must have form-level viewing access to that instrument.
3. A binding must have a valid MAC before its record context is trusted for
   access control. DAG lookup uses the current indexed record ID, so it remains
   correct after a record rename.
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

The Control Center page is available to users with REDCap's Control Center
dashboard access. Its link-display hook and controller factory both enforce
that requirement, so direct page access uses the same authorization boundary as
menu visibility. Plaintext e-Consent IP addresses remain separately restricted
to users who can access the enabled Database Query Tool.

The page is an exact global lookup only. It accepts either a capture-reference
suffix (normalized to `S:...`) or a positive numeric edoc ID by CSRF-protected
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

The project and administrator entry pages keep their separate authorization and
lookup setup, then pass a scope-specific view model to one shared rendering
partial. The partial contains only presentation logic; it uses REDCap's project
page heading style for project verification and the Control Center heading style
for administrator verification.

## Project configuration page

The project module link **Configure Watermarked Signatures** is available only to superusers and users with project design rights. Its backing project settings remain hidden in the standard External Module dialog, except for browser-debug output. The page validates the unbound-upload retention period, 1–20 character public project reference, image mode, custom-image rotation, and optional PNG upload before persisting through the framework setting API. The settings and project verification pages audit every watermark action tag. Historical 21–30 character project references remain valid in existing provenance and continue to render without a field reference.

Custom PNG uploads may be at most 6 MiB and 4096 pixels per side, subject to the renderer's 12-million-pixel input limit. Before creating the project edoc, the page decodes and normalizes the image with GD to at most 512 pixels per side and 1 MiB, preserving transparency and aspect ratio. The result must retain at least 16 pixels per side. The current stored image is retained when no replacement is uploaded, including while the REDCap-logo or no-image mode is selected. Custom-image rotation is an integer in the inclusive range -180 through 180; it is recorded in upload provenance with the selected and applied background modes and custom-image SHA-256.
