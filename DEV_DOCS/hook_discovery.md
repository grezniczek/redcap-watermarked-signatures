# Hook discovery: REDCap signature upload technical spike

## Target source inspected

The initial implementation was developed against the REDCap source available in
`/home/gr/redcap/codebase`.

## Page rendering

`redcap_data_entry_form` and `redcap_survey_page` run after REDCap has rendered
the file/signature dialog JavaScript. The module uses these hooks to:

1. enumerate action-tagged signature fields on the current instrument;
2. create one signed, short-lived envelope per field; and
3. wrap REDCap's global `filePopUp()` function so the correct envelope is added
   to the dynamically created iframe upload form.

This supports multiple signature fields because the wrapper selects the
envelope by the `fieldName` argument supplied by REDCap.

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

`DataEntry/file_upload.php` includes `Config/init_project.php` before it decodes
`myfile_base64`. During project initialization REDCap calls
`redcap_every_page_before_render`.

The module uses that hook only when the active request is the signature upload
receiver. At this point:

- REDCap has established the project, authentication/survey context, CSRF
  handling, metadata, and event;
- the posted base64 signature is still mutable; and
- `Files::uploadFile()` has not run.

The module verifies the envelope and replaces `$_POST['myfile_base64']` with the
server-rendered PNG. REDCap then continues through its normal upload path.

## Capturing the edoc ID

The upload receiver returns the new edoc ID in its iframe `stopUpload(...)`
JavaScript response. The module starts a request-scoped output buffer after
watermarking and parses that trusted server-generated response. Once the edoc ID
is present, it appends a `sigwm_upload` provenance event.

If REDCap reports a successful upload but the expected field/edoc response
shape cannot be recognized, the module leaves REDCap's response untouched and
appends a best-effort `sigwm_error_upload_provenance_response` diagnostic. If
the `sigwm_upload` write itself fails, it similarly attempts a
`sigwm_error_upload_provenance_logging` diagnostic containing safe capture
context and the technical error; an application-log entry remains the final
fallback if the EM log is unavailable. These diagnostics deliberately exclude
the envelope nonce and image bytes.

The EM framework itself buffers hook output and closes the topmost buffer as
soon as the hook returns. The module places an inert guard buffer above its
response-capture buffer; the framework consumes the guard, leaving the capture
buffer active for the subsequent output from `file_upload.php`.

The buffer does not alter the response.

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
failure terminates the upload request through the External Module framework's
`exitAfterHook()` mechanism. This prevents REDCap from silently storing the
unwatermarked payload.

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

The initial data-entry and survey render hooks do not provide an authoritative
record ID for every new-record flow. In the inspected REDCap source,
`DataEntry/index.php` invokes `redcap_data_entry_form` with a null record for a
new form, and `Surveys/index.php` can invoke `redcap_survey_page` with a null
record on the first public-survey page. The value eventually assigned by an
auto-numbered save must therefore not be captured early.

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
value (`data_entry` or `survey`) in every signed envelope. Upload interception
copies that trusted value into `sigwm_upload` and independently snapshots the
current authenticated username as nullable `capture_username`. Public surveys
therefore have an explicit survey origin and a null username; no survey hash is
stored.

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

REDCap 17.3.0 does not expose a dedicated External Module hook for record
renames. The module therefore records the two authenticated data-entry rename
paths that have a trusted server-side completion signal:

- For a record-ID change submitted with a data-entry form, REDCap retains the
  prior ID in `$_POST['__old_id__']` and calls `redcap_save_record` after the
  rename has completed. The module compares that prior ID with the authoritative
  hook record ID.
- The Record Home rename dialog posts to
  `DataEntryController:renameRecord`. Before that controller runs, the module
  resolves the pre-rename bound record. It observes the controller's server
  response and appends a rename event only when REDCap returns its success value
  (`1`), then resolves REDCap's final record-ID spelling after the rename.

In either path, a `sigwm_record_rename` event is appended only when an existing
module binding moved with the record. The event is indexed by the current record
ID and contains the old/new record IDs, origin, authenticated username, and UTC
timestamp. It is separate from the immutable binding payload, which remains a
record of the original signature context.

REDCap also updates the External Module log table's indexed `record` column for
all affected rows during a record rename. Verification deliberately uses that
current indexed value—not the MAC-protected, binding-time `record_id` in the
payload—for its live field read and DAG authorization. The authorized details
panel therefore displays the current record ID. The administrator-only technical
history retrieves the `sigwm_record_rename` entries indexed by that same current
record ID, preserving the old-to-new history without altering the binding.

The legacy API exposes a supported `redcap_module_api_before` hook after token
and `record_rename` authorization and before dispatching `API/record/rename.php`.
For `content=record` and `action=rename`, the module captures the supplied old
ID and `new_record_name`, then appends its event only after the API response
confirms `REDCap::renameRecord()` returned `true`. This adds `api` as a third
tracked rename origin without parsing REDCap's internal audit SQL.

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
