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
