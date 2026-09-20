# Hook discovery: REDCap signature upload technical spike

## Target source inspected

The initial implementation was developed against the REDCap source available in
`/home/gr/redcap/codebase`.

## Page rendering

`redcap_module_signature_upload_client_config` runs after REDCap has resolved
the current instrument and its signature fields and before it renders the
shared file/signature dialog. The module uses this hook to:

1. enumerate action-tagged signature fields on the current instrument;
2. create one signed, short-lived envelope per field; and
3. add the envelope to REDCap's field-specific hidden-input configuration.

REDCap owns the shared form lifecycle: it clears previously managed inputs and
adds only the values configured for the signature field whose dialog is being
opened. This supports multiple signature fields without replacing a browser
global or retaining stale values for ordinary uploads.

`@WATERMARKED-SIGNATURE` may carry one simple quoted field-reference parameter,
for example `@WATERMARKED-SIGNATURE="CONSENT"`. The module accepts a trimmed
1–16 character ASCII component using the project-reference alphabet. Project
references are capped at 20 characters. It signs the resolved component into
the envelope. A malformed, duplicate, or invalid parameter leaves the field
watermarked but omits that component from `REF:` and creates a capture-time
diagnostic. The project settings and project verification pages independently
audit every tag and report the affected field, reason, value length, and limit
where applicable.

## Upload interception

`DataEntry/file_upload.php` calls `redcap_module_signature_upload_before` only
after it has validated the signature field and event and decoded a non-empty
`myfile_base64` value. At this point:

- REDCap has established the project, authentication/survey context, CSRF
  handling, metadata, and event;
- the decoded PNG bytes are mutable by reference; and
- `Files::uploadFile()` has not run.

The module reads its signed envelope from the hook's untrusted scalar request
fields, verifies it against the trusted hook context, and replaces the
by-reference PNG with the server-rendered image. It no longer identifies the
receiver route or mutates `$_POST`. REDCap writes the final PNG to a temporary
file only after all enabled modules have run without appending an error.

## Capturing the edoc ID

After REDCap has stored and mapped the final PNG,
`redcap_module_signature_upload_after` supplies the authoritative edoc ID,
file size, and SHA-256 digest. The module matches this callback to the
request-scoped provenance prepared by the before hook and then appends the
`sigwm_upload` event. It does not inspect or alter REDCap's iframe response.

If the post-storage context is invalid, the module appends a best-effort
`sigwm_error_upload_provenance_after` diagnostic. If the `sigwm_upload` write
itself fails, it similarly attempts a
`sigwm_error_upload_provenance_logging` diagnostic containing safe capture
context and the technical error; an application-log entry remains the final
fallback if the EM log is unavailable. These diagnostics deliberately exclude
the envelope nonce and image bytes.

The action-only after hook emits no output. REDCap computes the provenance
digest from the final PNG after all before-hook transformations, so the digest
also covers a valid transformation made by a later enabled module.

## WM1 image format

Watermark format version 1 is rendered entirely by the server with GD. The
source PNG is decoded under byte, dimension, and pixel limits and normalized
onto an opaque white true-color canvas. Output retains the source height plus a
38-pixel footer. Sources narrower than 300 pixels are centered on a 300-pixel
canvas so neither footer line needs to truncate its identifiers.

The visible layout is deterministic for identical source bytes and watermark
values:

1. normalized signature raster;
2. repeated compact anchor/context/capture text, with a white edge and blue
   center so crossings remain visible over both white and dark strokes;
3. an opaque footer containing the full stable anchor, context reference,
   capture reference, format marker, and server-generated UTC timestamp.

The renderer accepts only the WM1 Base32 identifier shapes and an ISO 8601 UTC
timestamp ending in `Z`. The SHA-256 digest is computed over the final encoded
PNG and stored in both upload provenance and the later MAC-protected binding.
The optional visible reference is a 20-character project component, a
16-character field component, or both separated by `:`; its maximum rendered
length is therefore 37 characters. This extends WM1 without changing its
footer structure or identifier semantics.

## Failure behavior

For an action-tagged signature field, a missing/invalid envelope or rendering
failure appends a safe error to the before-upload hook's shared error list.
REDCap then returns its ordinary upload-failure response without creating a
temporary file or edoc. The module writes no HTTP response from the hook. This
prevents REDCap from silently storing the unwatermarked payload.

## Save-time binding

`redcap_save_record` is the selected post-save hook. REDCap calls it after the
record has been saved and passes the authoritative record, instrument, event,
and repeat instance.

The module re-reads only the configured signature fields through
`REDCap::getData()` and normalizes the three storage shapes:

- classic/non-repeating event data;
- repeating-event data, whose repeat-instrument key is an empty string; and
- repeating-instrument data, whose repeat-instrument key is the form name.

Only the edoc actually persisted in the field is considered. An edoc without a
`sigwm_upload` event is treated as a pre-module signature and ignored.

Binding is serialized with a MySQL/MariaDB named lock derived only from the
globally unique edoc ID. Inside the lock, the module queries across all projects
using this module and checks again for the first `sigwm_bind`
event. No existing binding produces one MAC-protected append; an identical
binding is an idempotent no-op; and a different binding produces only a
`sigwm_error_edoc_already_bound` event.

The successful binding repeats the visible anchor as an indexed log parameter
and inside `payload_json`. This makes the identifier printed in the image
directly inspectable on the authoritative binding entry. The anchor is included
in the binding MAC alongside the scope values from which it is derived.

REDCap may route ordinary `SELECT` statements to a read replica. The lock
acquire/release, protected binding lookup, and record-binding lookups that
immediately follow a rename therefore force the primary database connection.
The EM framework still expands the log pseudo-query before it is executed. This
prevents replica lag from allowing a duplicate binding or suppressing a
completed rename's audit event.

## Multi-field and signature lifecycle behavior

Each action-tagged signature field receives a separately signed field-scoped
envelope and context reference. The browser replaces the hidden envelope value
whenever another field's dialog opens and removes it for ordinary uploads, so a
reused REDCap upload form cannot submit a stale field envelope.

Save-time processing is deliberately driven by persisted field values rather
than by every upload made from the page:

- delete/redraw before save leaves earlier uploaded edocs unbound;
- abandoning the form produces upload provenance but no binding;
- multiple persisted signature fields bind independently;
- clearing a field does not delete or alter its historical binding; and
- replacing a signature in a later save retains the old binding and creates an
  independent binding for the new edoc.

For repeating instruments, bindings store the form name and authoritative hook
instance. For repeating events, the repeat instrument is explicitly `null` and
the authoritative event instance is stored. The stable visible anchor remains
limited to project, event, instrument, field, and watermark version because the
repeat instance may be unknown when upload occurs.

## New records and first-page surveys (Phase 4B)

The client-configuration hook does not provide an authoritative record ID for
every new-record flow. In the inspected REDCap source, it receives a null
record for a new data-entry form and for the first public-survey page. The value
eventually assigned by an auto-numbered save must therefore not be captured
early.

Capture envelopes deliberately contain `record_ref: null` and no `record_id`.
They carry the stable project, event, instrument, and field scope plus a random
field-specific `context_ref`. This reference connects upload provenance to the
later save without placing a tentative record identifier in the signed envelope
or immutable image. Stable record pseudonyms are deferred beyond the first
milestone, as permitted by the implementation plan.

`field_reference` is optional for compatibility with envelopes and provenance
created before field marks were introduced. New envelopes include it (or an
internal configuration-error code when it was deliberately omitted). New
upload/binding pairs use provenance format `v: 2`. Their `binding_mac` retains
the released v1 payload exactly, allowing a v1.0.2 verifier to validate the
base MAC and matched upload/binding pair. A separately derived
`binding_extension_mac` authenticates `field_reference` together with the
format version and base MAC. Current verification requires that extension MAC
for v2; v1 bindings without it continue to verify. The short-lived development
format that placed `field_reference` directly in a v1 base-MAC payload remains
accepted for already captured development signatures.

The provenance `v` is not the visible `WM1` marker or the signed-envelope
version. When a future binding extension is needed, keep the established base
MAC schema intact, protect the new values with an extension MAC bound to the
base MAC, write the new `v` consistently to upload and binding events, and
regression-test the preceding verifier's base-MAC behavior.

After REDCap creates the record, its post-save path invokes
`redcap_save_record` with the authoritative record ID. The module reads the edoc
that REDCap actually persisted and binds that edoc, its upload provenance, and
the pre-save context reference to the authoritative record. The same flow is
used for auto-numbered data-entry records and records created by first-page
public surveys.

If record creation or the survey submission is abandoned or fails, the
post-save hook cannot create a binding. The uploaded edoc retains its
`sigwm_upload` provenance only, which makes the unsuccessful capture auditable
without falsely associating it with a record.

## Capture origin and actor audit fields

The data-entry and survey rendering hooks place a mandatory `capture_origin`
value (`data_entry` or `survey`) in every signed envelope. The before-upload
hook verifies that signed value against REDCap's independently derived capture
origin, copies it into `sigwm_upload`, and snapshots the current authenticated
username as nullable `capture_username`. Public surveys therefore have an
explicit survey origin and a null username; no survey hash is stored.

`redcap_save_record` independently derives `save_origin` from its trusted survey
hook arguments and snapshots `save_username`. The first binding is created only
when capture and save origins match. A mismatch produces
`sigwm_error_origin_mismatch`, with both origins and nullable usernames directly
inspectable, and no `sigwm_bind`.

All four audit fields are retained in the binding payload and protected by the
binding MAC. Usernames are operator metadata, not signer identity, and differing
capture/save usernames do not prevent binding.

Origin equality applies to creation of the first binding. An already-bound
survey signature may legitimately be encountered during a later staff save of
the same form. Such saves remain idempotent and preserve the original binding's
survey origin instead of creating a false mismatch error.

## Record-rename tracking

`redcap_module_record_rename_after` supplies the previous record ID and final
canonical record ID after REDCap has completed a successful rename. It runs
once for the data-entry form, Record Home, API, and supported programmatic
paths, including one callback for a logical multi-arm rename rather than one
callback per internal arm update.

The module resolves the binding by the final record ID after REDCap has moved
the External Module log indexes. It appends `sigwm_record_rename` only when an
existing module binding moved with the record. The event is indexed by the
current record ID and contains the old/new IDs, affected arm or cross-arm
scope, trusted origin, authenticated username when available, and UTC
timestamp. It is separate from the immutable binding payload, which remains a
record of the original signature context.

REDCap also updates the External Module log table's indexed `record` column for
all affected rows during a record rename. Verification deliberately uses that
current indexed value—not the MAC-protected, binding-time `record_id` in the
payload—for its live field read and DAG authorization. The authorized details
panel therefore displays the current record ID. The administrator-only technical
history retrieves the `sigwm_record_rename` entries indexed by that same current
record ID, preserving the old-to-new history without altering the binding. The
module no longer inspects route-specific request values or response output to
infer rename completion.

## Verification backend (Phase 5A)

Exact verification lookup uses the complete capture reference and can be
restricted to a project or run globally for a later administrator caller. The
lookup rejects duplicate capture-reference, upload-edoc, or binding-edoc events
instead of silently choosing one.

Edoc existence and bytes are obtained through `Files::getEdocInfo()` and
`Files::getEdocContentsAttributes()`, preserving REDCap's configured local or
external storage abstraction. The verifier recomputes the SHA-256 digest but
does not return file contents. Current-field comparison reads the normalized
classic, repeating-instrument, or repeating-event location only after the
binding MAC, required binding-extension MAC, upload relationship, and anchor
have been trusted.

The verification service deliberately performs no user-rights or DAG decision.
That authorization boundary belongs to the project and administrator UI slices
that consume the documented result contract.

## Project verification page (Phase 5B)

`pages/verify-signature.php` is registered as an authenticated project link with
REDCap's header and footer. Link visibility is expanded beyond REDCap's default
design-rights rule only when the current user has viewing rights to at least one
instrument containing an enabled signature field. The access policy obtains
those rights from REDCap's native `data_entry` form-rights string and delegates
its parsing and no-access decision to `UserRights`; it does not duplicate or
reinterpret REDCap's legacy and bitmask encodings.

The page posts the full capture reference with REDCap CSRF protection. Its
controller performs a project-scoped preflight before invoking full
verification: form-level viewing rights are checked against the captured
instrument, the binding MAC is validated before trusting the record ID, and a
DAG-restricted user must belong to the bound record's DAG. Unbound uploads are
not inspectable by DAG-restricted users because they have no authoritative DAG
context.

The visible image uses `S:` as a label and prints only the grouped reference
suffix. The page mirrors that representation with a fixed `S:` input prefix and
normalizes the entered suffix to the canonical `S:...` lookup value.

Only allowlisted verification fields reach the page. Raw log payloads and
cryptographic transport values remain backend-only.
