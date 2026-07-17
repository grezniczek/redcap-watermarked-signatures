# REDCap External Module: Context-Bound Signature Watermark
## Detailed implementation plan for a first Codex-assisted implementation

**Working title:** `REDCap Signature Watermark`  
**Status:** Architecture agreed sufficiently for an initial implementation  
**Primary purpose:** Reduce the risk that a signature image captured in a REDCap signature field is reused outside the context in which it was originally captured.


## 0. Tooling hints

node is available here:
```bash
/home/gr/.nvm/versions/node/v22.22.3/bin/node 
```

---

## 1. Objective

The module adds a visible, context-bound watermark to newly captured REDCap signature images, whether the signature was drawn or typed.

The watermark is intended to make reuse of the image in another context detectable and conspicuous. It is not intended to provide a qualified electronic signature, prove the identity of the signer, or cryptographically bind an entire document or PDF.

The module should:

1. Watermark every newly captured signature before REDCap stores the corresponding edoc.
2. Ensure that the image visibly contains compact identifiers and a cryptographic anchor.
3. Bind the immutable edoc exactly once to its authoritative REDCap context after the form save.
4. Support new records, surveys, repeating instruments, newly created repeat instances, and multiple signature fields on one page.
5. Avoid exposing the literal field name, form name, event, record ID, or repeat instance in the visible image.
6. Permit later verification through project-scoped and administrator-scoped facilities.
7. Ignore all signatures that existed before the module began handling the field.

---

## 2. Important REDCap constraints

The implementation must be designed around the following constraints.

### 2.1 Immutable edocs

Once REDCap stores an edoc, its content is immutable. It may only be replaced by creating another edoc and changing the field value.

The module will therefore **not** use a provisional image followed by a post-save image replacement. The watermark written during upload is final.

Late-known context is attached through an append-only binding, not by modifying the image.

### 2.2 Signature uploads use an iframe

REDCap submits signature images through an iframe-based upload flow. The upload may create an edoc that is never ultimately saved into a record field.

This can occur when:

- the signature is deleted and redrawn before the form is submitted;
- the form is abandoned;
- the form submission is cancelled;
- another captured signature replaces the first one before save;
- a save fails.

An edoc created by the iframe upload is therefore only a candidate signature upload until the main form save confirms that the signature field actually contains that edoc ID.

### 2.3 Upload receiver can be hooked

The module can hook into the server-side file that receives the iframe POST and can manipulate the submitted payload before REDCap stores it.

This upload receiver is the authoritative watermarking point.

### 2.4 No dedicated database table

A dedicated module table is not acceptable.

Persistent state must use the External Module log table, treated as append-only storage. The log table has adequate indexing and can support structured storage through event types and JSON payloads.

### 2.5 Field names are stable

Production REDCap fields cannot be renamed. The field name is therefore a stable scope anchor.

The field name may appear in HTML, JavaScript, JSON, requests, logs, and developer tools. It must simply not be printed visibly into the signature image or appear in exported/printed renderings of the image.

### 2.6 Existing signatures are outside the module scope

The module must ignore pre-existing signatures completely.

It must not:

- add a status to them;
- migrate them automatically;
- create pseudonyms for them;
- claim that they were captured under the watermarking process.

---

## 3. Security and trust model

### 3.1 Threat addressed

The module addresses reuse of a signature image outside its original REDCap context, for example:

- copying a signature image into another record;
- assigning the same edoc to another signature field;
- exporting the signature and placing it into another document;
- reusing the image in another project, event, form, or field.

The watermark should make such reuse detectable either visually or through verification.

### 3.2 Threats not addressed

The module does not by itself prove:

- the real-world identity of the person who created the signature;
- that the signer read or approved the entire surrounding document;
- that an exported PDF has not been modified;
- that the browser or REDCap server was uncompromised;
- that an administrator with unrestricted database and filesystem access could not bypass the module;
- that a determined image editor cannot remove or reconstruct portions of the signature.

### 3.3 Trust boundaries

The client is not trusted to provide authoritative context values.

Any context transmitted through the browser must be integrity-protected and verified server-side. The browser may carry the field-specific envelope, but may not define or modify its trusted contents.

The authoritative components are:

- the module-generated and signed field envelope;
- the upload receiver;
- REDCap’s stored edoc ID;
- the successful REDCap form save;
- the append-only binding record;
- the REDCap-instance-bound secret used for key derivation.

---

## 4. Core architectural principle

The implementation uses:

> **One-stage immutable image generation, followed by two-stage context binding.**

### Stage 1: upload-time image creation

At the iframe upload receiver:

1. Verify the signed envelope for the specific signature field.
2. Derive the stable-scope cryptographic anchor.
3. Generate a unique capture reference.
4. Add the final visible watermark to the signature raster.
5. Allow REDCap to store the modified PNG as an immutable edoc.
6. Record the upload provenance once the edoc ID is known.

### Stage 2: save-time authoritative binding

After a successful form save:

1. Read the edoc ID actually persisted in each configured signature field.
2. Locate the corresponding upload provenance.
3. Resolve the complete REDCap context, including record and repeat instance.
4. Bind that edoc exactly once.
5. Reject any conflicting second binding by logging an error only.

The image is never rewritten after Stage 1.

---

## 5. Terminology and identifiers

The module should distinguish three concepts.

## 5.1 Stable-scope anchor

The **anchor** is a compact visible digest derived from the stable scope that is always known before upload:

- watermark format version;
- project ID;
- event ID;
- instrument/form name;
- field name.

Conceptually:

```text
anchor = truncate_base32(
    HMAC-SHA-256(
        K_anchor,
        canonical_scope
    )
)
```

The REDCap-instance-bound secret contributes to `K_anchor`. The secret itself is never exposed.

Only the resulting compact digest is printed in the image.

Example:

```text
7K4M-P8Q2-X5DN
```

The anchor allows the module to recompute the digest from the visible presentation context and verify that the signature was originally prepared for the same project, event, form, and field.

The literal field name and other scope components are not printed into the image.

## 5.2 Context reference

The **context reference** is a pseudonymous identifier for the field-specific record context.

It ultimately represents:

- project;
- record pseudonym;
- event;
- instrument/form;
- field;
- repeat instrument;
- repeat instance.

The context reference must include the field semantically. Two signature fields on the same form and repeat instance must have different context references.

Example:

```text
C-8D3Q-K7H2-R5NW
```

The context reference may be created before all context components are known. It is later bound to the complete saved context.

Repeated captures for the same field during the same page context normally reuse the same context reference.

## 5.3 Capture reference

The **capture reference** uniquely identifies one particular signature image upload.

Every redraw or typed-signature recreation receives a new capture reference.

Example:

```text
S-5N6T-P4WC-X8Q2
```

The capture reference should be generated server-side at the upload receiver, not accepted as authoritative client input.

---

## 6. Record pseudonyms and record renames

The module may use a stable record pseudonym rather than print or expose the actual REDCap record ID in the image.

Example:

```text
R-7M4K-2C9P
```

Requirements:

1. The pseudonym remains stable if the REDCap record ID is renamed.
2. Record renames are tracked through append-only log events.
3. No signature image is rewritten after a record rename.
4. Historical bindings remain valid.
5. The verification interface may show the current record ID and rename history to authorized users.
6. The actual record ID is never part of the visible watermark unless a future configuration explicitly introduces that option.

The first implementation may defer record pseudonyms if necessary, but the internal data model and binding format should allow them without redesign.

### First-release decision: do not implement record pseudonyms

Record pseudonyms are deliberately out of scope for the first release. They
would provide a stable opaque identifier for correlating several signatures
from the same record without disclosing the REDCap record ID. That is not
needed by the authenticated verification facilities implemented here:

- the image never visibly contains the record ID;
- the capture reference provides exact image lookup;
- the field-scoped context reference identifies the captured context without
  revealing its components;
- the MAC-protected binding retains the historical record context; and
- REDCap's current indexed log record and the append-only rename history
  resolve current identity and record renames for authorized users.

A stable visible pseudonym would also make otherwise separate signatures
linkable to the same record, which is an unnecessary privacy cost for the
current workflow. The binding format retains `record_ref: null` as an explicit
extension point. Reconsider pseudonyms only for a concrete future workflow
that requires cross-signature record correlation without revealing the record
ID, such as an external or semi-public verification service.

---

## 7. Per-field signed envelope

There will be one capture envelope per signature field rendered on the page.

The envelope is not required to be encrypted because its contents are already visible in the page or browser tools. It must, however, be signed to prevent tampering.

A suitable transport form is:

```text
base64url(canonical_json) + "." + base64url(hmac)
```

### 7.1 Minimum envelope contents

```json
{
  "v": 1,
  "pid": 123,
  "event_id": 417,
  "instrument": "consent",
  "field": "participant_signature",
  "capture_origin": "data_entry",
  "context_ref": "C-8D3Q-K7H2-R5NW",
  "record_ref": "R-7M4K-2C9P",
  "issued_at": 1784212200,
  "expires_at": 1784219400,
  "nonce": "base64url-random-value"
}
```

Depending on what is reliable in the relevant REDCap context, the envelope may additionally contain:

- survey response/session reference;
- page/request identifier;
- current record ID when already known;
- module configuration version;
- watermark layout version;
- expected field type;
- expected upload purpose, fixed to `signature`.

`capture_origin` is mandatory and is set by the server-side rendering hook to
either `data_entry` or `survey`. The authenticated username is deliberately not
accepted from the envelope; it is snapshotted independently by the server when
the upload provenance event is created.

### 7.2 Envelope reuse

The field envelope represents authorization to upload a signature for that field during the current page/session context.

It may be reused for:

- deleting and redrawing a signature;
- typed-signature recreation;
- legitimate iframe transport retries.

Each accepted upload still receives a new capture reference and normally a new edoc ID.

### 7.3 Envelope expiry

The envelope should be short-lived but long enough for realistic data entry and survey completion.

The exact default should be configurable or selected conservatively. For a first implementation, a duration of a few hours is more practical than a very short interval.

An expired envelope must not be accepted for watermarking.

---

## 8. Cryptographic construction

## 8.1 Key derivation

Do not use the REDCap-instance secret directly for all purposes.

Derive purpose-specific keys, conceptually:

```text
K_envelope = HKDF(instance_secret, "sigwm/envelope/v1")
K_anchor   = HKDF(instance_secret, "sigwm/anchor/v1")
K_binding  = HKDF(instance_secret, "sigwm/binding/v1")
K_refs     = HKDF(instance_secret, "sigwm/references/v1")
```

If HKDF is not conveniently available in the supported PHP environment, an equivalent carefully separated HMAC-based derivation may be used.

The implementation must not invent a weak project-local secret or expose the instance secret through configuration pages or logs.

## 8.2 Canonicalization

Every HMAC input must use deterministic canonicalization.

Recommended rules:

- UTF-8;
- explicit version;
- fixed property order;
- no omitted null-equivalent fields unless specified by the format;
- integers serialized as base-10 integers;
- strings serialized without locale transformations;
- no concatenation without delimiters or length encoding;
- preferably canonical JSON generated by a dedicated helper.

Example stable scope:

```json
{
  "v": 1,
  "pid": 123,
  "event_id": 417,
  "instrument": "consent",
  "field": "participant_signature"
}
```

## 8.3 Anchor length and encoding

Base32 is preferred over hexadecimal because it carries more bits per character and is easier to group visibly.

A first implementation should use approximately 60–80 visible bits.

For example:

- 12 Base32 characters = 60 bits;
- 13 Base32 characters = 65 bits;
- 16 Base32 characters = 80 bits.

A practical initial choice is 13 or 16 characters, grouped with hyphens.

Example:

```text
7K4M-P8Q2-X5DN-R
```

or:

```text
7K4M-P8Q2-X5DN-R7CW
```

The precise length should be centralized as a format constant.

## 8.4 Binding MAC

The late-known authoritative context must be protected by a binding MAC stored in the append-only log entry.

Conceptually:

```text
binding_mac = HMAC-SHA-256(
    K_binding,
    canonical(
        edoc_id,
        anchor,
        capture_ref,
        context_ref,
        record_ref,
        capture_origin,
        capture_username,
        save_origin,
        save_username,
        actual_record_id,
        project_id,
        event_id,
        instrument,
        field,
        repeat_instrument,
        repeat_instance,
        final_file_digest
    )
)
```

This does not place the late-bound values into the image. It protects the stored binding against undetected alteration.

---

## 9. Visible watermark design

The final image should contain two visual components.

## 9.1 Repeated overlay

A faint repeated pattern crossing the entire signature area.

Requirements:

- rendered **after** the signature, so that watermark elements cross signature strokes;
- deterministic placement;
- low but readable opacity;
- no use of `Math.random()`;
- repeated sufficiently often that cropping does not remove all identifiers;
- should contain compact identifiers only;
- should remain readable after common PDF embedding and printing.

Possible repeated text:

```text
7K4M-P8Q2 · C8D3Q-K7H2 · S5N6T-P4WC
```

The overlay may use shortened forms of the full context and capture references if the full versions are also printed in the footer.

## 9.2 Readable footer or context band

A compact band should provide the full visible identifiers and timestamp.

Example:

```text
WM1 · A:7K4M-P8Q2-X5DN · C:8D3Q-K7H2-R5NW
S:5N6T-P4WC-X8Q2 · 2026-07-16T14:32:05Z
```

The footer must not contain:

- raw field name;
- form name;
- event name;
- project title;
- record ID;
- repeat instance.

It may contain a configurable project or institution logo, but the identifiers must remain meaningful without the logo.

## 9.3 Rendering order

Recommended order:

1. Create a normalized output canvas.
2. Draw the signature raster.
3. Draw the repeated watermark overlay on top of the signature.
4. Draw the readable footer/context band.
5. Encode the final PNG.
6. Compute the final PNG digest.
7. Pass the modified payload to REDCap storage.

## 9.4 Timestamp

Use a server-generated UTC timestamp in ISO 8601 form.

Do not use browser locale strings.

Example:

```text
2026-07-16T14:32:05Z
```

Higher subsecond precision may be stored internally but need not be printed.

## 9.5 Deterministic layout

The layout should be deterministic based on:

- watermark format version;
- output dimensions;
- capture reference or a deterministic derivative.

Avoid random offsets. Determinism simplifies testing and reproducibility.

---

## 10. Upload-time processing

## 10.1 Browser responsibilities

The browser:

1. Renders one signed envelope per signature field.
2. Associates the correct envelope with the field’s signature upload.
3. Sends the original signature raster and signed envelope through the existing iframe flow.
4. Does not compute authoritative anchors.
5. Does not generate authoritative capture references.
6. Does not make security decisions based on unverified JSON values.

JavaScript may display previews or facilitate transport, but server-side rendering is authoritative.

## 10.2 Upload receiver responsibilities

The upload receiver hook must:

1. Detect that the incoming upload is a REDCap signature upload handled by the module.
2. Extract the field-specific signed envelope.
3. Verify the envelope HMAC using constant-time comparison.
4. Validate its version and expiry.
5. Confirm the project has the module enabled.
6. Confirm the project ID matches the active project.
7. Confirm the field exists.
8. Confirm the field belongs to the stated instrument.
9. Confirm the instrument is valid for the stated event.
10. Confirm the field is a REDCap signature field.
11. Confirm the field is configured for watermarking.
12. Validate any authenticated-user, survey-session, or page binding that is included.
13. Recompute the stable-scope anchor from trusted envelope values.
14. Generate a fresh capture reference.
15. Render the visible watermark server-side.
16. Replace the submitted PNG payload with the watermarked PNG.
17. Compute and retain the final PNG SHA-256 digest.
18. Allow the normal REDCap upload process to create the immutable edoc.
19. Capture the returned edoc ID.
20. Append the upload provenance event to the EM log.

The receiver must never trust a client-provided visible anchor, capture reference, file digest, or watermark timestamp.

---

## 11. Upload provenance event

After REDCap creates the edoc, append a structured event.

Example event type:

```text
sigwm_upload
```

Example payload:

```json
{
  "v": 1,
  "capture_ref": "S-5N6T-P4WC-X8Q2",
  "context_ref": "C-8D3Q-K7H2-R5NW",
  "record_ref": "R-7M4K-2C9P",
  "capture_origin": "data_entry",
  "capture_username": "alice",
  "anchor": "7K4M-P8Q2-X5DN-R7CW",
  "pid": 123,
  "event_id": 417,
  "instrument": "consent",
  "field": "participant_signature",
  "edoc_id": 98137,
  "captured_at": "2026-07-16T14:32:05.381Z",
  "file_sha256": "hex-or-base64url-digest",
  "envelope_nonce": "base64url-value",
  "watermark_version": 1
}
```

The upload provenance establishes:

```text
edoc_id ↔ capture_ref ↔ context_ref ↔ stable scope ↔ final file digest
```

It does not yet prove that the edoc was saved into a record field.

---

## 12. Save-time binding

After a successful REDCap form save, the module must inspect each configured signature field in the saved context.

For every non-empty signature field:

1. Obtain the persisted edoc ID.
2. Find the upload provenance event for that edoc.
3. Confirm that the provenance project, event, instrument, and field match the saved location.
4. Recompute and verify the stable-scope anchor.
5. Resolve:
   - actual record ID;
   - record pseudonym;
   - event ID;
   - instrument/form;
   - field;
   - repeat instrument;
   - repeat instance.
6. Attempt the one-time binding operation.
7. Append the successful binding event only if the edoc has no prior binding.
8. Treat an identical repeated invocation as an idempotent no-op.
9. Treat a conflicting prior binding as an error and do not alter any existing state.

The save hook must not assume that every edoc uploaded on the page was saved. It only binds the edoc ID actually present in the persisted field.

---

## 13. One-edoc-one-binding invariant

### 13.1 Hard rule

An edoc ID may be successfully bound at most once.

The first successful binding is authoritative.

### 13.2 Idempotent duplicate

If the same binding is encountered again with all binding-defining values identical, treat it as a no-op.

Do not append unnecessary duplicate binding events unless implementation constraints make a diagnostic event useful.

### 13.3 Conflicting rebinding attempt

If an edoc already has a successful binding and any binding-defining value differs, the module must:

1. Keep the original binding unchanged.
2. Create no second binding.
3. Make no data change.
4. Append an error log event only.

A conflict may involve a different:

- project;
- record or record pseudonym;
- event;
- repeat instrument;
- repeat instance;
- instrument;
- field;
- context reference;
- capture reference.

### 13.4 Concurrency protection

The EM log table does not provide a unique database constraint on edoc ID.

The binding operation therefore requires serialization, preferably through a database advisory/named lock keyed by the edoc ID.

Conceptual lock name:

```text
sigwm:bind:<edoc_id>
```

Within the lock:

1. Query again for an existing successful binding.
2. Compare it with the proposed binding.
3. Insert only if none exists.
4. Log a conflict if it differs.
5. Release the lock.

This provides at-most-once behavior through module-controlled code paths.

---

## 14. Successful binding event

Example event type:

```text
sigwm_bind
```

Example payload:

```json
{
  "v": 1,
  "anchor": "7K4M-P8Q2-X5DN-R7CW",
  "capture_ref": "S-5N6T-P4WC-X8Q2",
  "context_ref": "C-8D3Q-K7H2-R5NW",
  "record_ref": "R-7M4K-2C9P",
  "capture_origin": "data_entry",
  "capture_username": "alice",
  "save_origin": "data_entry",
  "save_username": "alice",
  "record_id": "10427",
  "pid": 123,
  "event_id": 417,
  "instrument": "consent",
  "field": "participant_signature",
  "repeat_instrument": "consent",
  "repeat_instance": 3,
  "edoc_id": 98137,
  "bound_at": "2026-07-16T14:34:11.912Z",
  "file_sha256": "hex-or-base64url-digest",
  "binding_mac": "base64url-hmac",
  "watermark_version": 1
}
```

Use explicit `null` values for non-repeating contexts if that is part of the canonical binding format.

The capture and save origins are derived independently and must match when the
first binding is created. A mismatch creates `sigwm_error_origin_mismatch` and
no successful binding. Once an edoc is already bound, later saves remain
idempotent even if the form is subsequently opened through another channel; the
stored origin fields continue to describe the original capture and first
successful binding.

The username fields are nullable server-side snapshots of the authenticated
REDCap operator at each stage. They identify neither a public survey respondent
nor the person represented by the signature. A difference between capture and
save usernames is retained for audit but does not block binding. Survey hashes
must never be logged.

---

## 15. Error events

Suggested event types:

```text
sigwm_error_invalid_envelope
sigwm_error_expired_envelope
sigwm_error_scope_mismatch
sigwm_error_origin_mismatch
sigwm_error_missing_provenance
sigwm_error_edoc_already_bound
sigwm_error_capture_edoc_conflict
sigwm_error_upload_render
sigwm_error_binding_mac
sigwm_error_file_digest
```

A general event type with an error code inside the JSON is also acceptable if it produces more efficient indexed queries.

A conflicting rebinding event should record:

- edoc ID;
- original binding reference or identifying values;
- attempted binding values;
- timestamp;
- request/hook context;
- authenticated username where available;
- survey context where applicable;
- a concise technical message.

Do not include image bytes or unnecessary personal data in error logs.

---

## 16. Multiple signature fields on one page

Each signature field receives:

- its own signed envelope;
- its own field-scoped context reference;
- its own stable-scope anchor;
- a new capture reference for every upload;
- its own edoc provenance and later binding.

Example:

```text
Field A:
    context C1
    capture S1 → edoc 1001
    capture S2 → edoc 1002

Field B:
    context C2
    capture S3 → edoc 1003
```

If the saved form contains edoc 1002 in Field A and edoc 1003 in Field B:

- edoc 1002 is bound to C1 and Field A;
- edoc 1003 is bound to C2 and Field B;
- edoc 1001 remains unbound.

---

## 17. New records and first-page surveys

The first implementation must support cases in which the record ID is not yet known when the signature is captured.

The solution is preallocation of pseudonymous references:

- record reference, if record pseudonyms are implemented initially;
- field-scoped context reference.

The signed envelope contains these references before upload.

After the successful save creates or resolves the actual record ID, the binding event attaches the pseudonyms to the authoritative record context.

No image rewrite is required.

The implementation must carefully inspect how REDCap identifies:

- a newly created record in data entry;
- a first-page survey response;
- an auto-numbered record;
- a survey response before the record name is exposed;
- failed or cancelled creation.

---

## 18. Repeating instruments and unknown repeat instances

The repeat instance may not be known when a signature is uploaded.

The stable-scope anchor intentionally excludes the repeat instance because it is not always known before upload. It covers the always-known scope:

```text
project + event + instrument + field + watermark version
```

The field-scoped context reference is later bound to the authoritative repeat instance after save.

The binding event must distinguish:

- non-repeating instrument;
- repeating instrument;
- repeating event where applicable;
- actual repeat instrument;
- actual repeat instance.

The exact REDCap representation must be discovered and normalized in a dedicated context helper.

---

## 19. Delete, redraw, abandon, replace, and clear scenarios

### 19.1 Delete and redraw before save

Each upload receives a new capture reference and edoc.

Only the edoc actually stored in the saved signature field is bound.

Earlier uploads remain unbound.

### 19.2 Form abandoned or cancelled

The uploaded edoc remains unbound.

No binding event is created.

The upload provenance may be purged later according to retention policy.

### 19.3 Signature replaced in a later save

The old edoc retains its original binding.

The new edoc receives a new capture reference and its own one-time binding.

The verification page may determine whether the old edoc is still the current field value.

No image or previous binding is rewritten.

### 19.4 Signature field cleared later

The historical binding remains valid as a record of the original capture context.

The verification facility may report that the edoc is no longer the current value of the field.

A dedicated “cleared” event is optional and not required for the first implementation.

### 19.5 Existing signature encountered

Ignore it unless it has upload provenance created by this module.

Do not create an error merely because a configured field contains a pre-existing edoc without module provenance.

This distinction is important during module rollout.

---

## 20. Log retention

### 20.1 Durable entries

The following should normally be retained for as long as verification is promised:

- successful binding events;
- record pseudonym creation events;
- record rename events;
- serious binding conflict/error events.

### 20.2 Temporary entries

Unbound upload provenance may be purged after a configurable period.

The implementation uses a project-level retention setting with a default of 90
days. A daily module cron purges only expired `sigwm_upload` entries that have
no `sigwm_bind` event; a value of `0` disables automatic purging. Malformed
upload provenance is retained for investigation rather than silently removed.

### 20.3 No image duplication

Do not store:

- raw signature images;
- copies of watermarked images;
- base64 image payloads;
- canvas data;
- full PDFs.

The edoc remains the sole image storage.

---

## 21. Verification facilities

Two verification scopes are desirable.

The shared backend must accept only a complete exact capture reference and
return separate binding, integrity, and current-field conclusions. It must not
serve as an authorization layer: project and administrator callers enforce
their respective REDCap permissions before displaying record, actor, or
technical details. The first implementation uses the statuses
`invalid_reference`, `unknown`, `unbound`, `invalid`, `incomplete`,
`valid_current`, and `valid_historical`.

## 21.1 Project-scoped verification

Accessible only to users with appropriate project rights.

Lookup should require an exact high-entropy identifier, preferably the full capture reference.

The page may show:

- verification result;
- project;
- current record ID subject to rights;
- record pseudonym;
- event;
- form/instrument;
- field;
- repeat instrument;
- repeat instance;
- capture timestamp;
- binding timestamp;
- edoc ID where appropriate;
- whether the edoc still exists;
- whether the field currently points to that edoc;
- stable-scope anchor verification;
- final file digest verification;
- binding MAC verification.

The page must respect REDCap data-access groups and other relevant access restrictions.

The project page is linked through the External Module `config.json`. Link and
page access require viewing rights to at least one enabled signature
instrument. Exact-result access additionally requires viewing rights to the
captured instrument and, for a bound result, membership in the record's DAG
when the user is DAG-restricted. Unbound uploads are withheld from
DAG-restricted project users because no authoritative record/DAG exists yet.

## 21.2 Global administrator verification

Accessible only to REDCap administrators.

It may additionally show:

- project ID;
- technical log entries;
- upload provenance;
- binding conflict history;
- record rename history;
- unbound upload diagnostics;
- file digest mismatches;
- module version and watermark version.

The global page should be an exact-lookup facility, not a browsing interface listing all signatures.

## 21.3 Independent stable-scope verification

When a signature is visibly presented in REDCap, the module can obtain the current:

- project;
- event;
- instrument;
- field.

It can recompute the stable-scope anchor and compare it with the anchor associated with the image/provenance.

This check does not depend solely on trusting the later context binding.

---

## 22. File-integrity verification

At upload time, compute SHA-256 of the final watermarked PNG bytes and store it in the upload provenance and binding.

At verification time:

1. Retrieve the current edoc bytes.
2. Recompute SHA-256.
3. Compare with the stored digest.

A mismatch indicates that the stored file no longer matches the originally watermarked PNG.

This exact-byte verification will not survive:

- PNG re-encoding;
- resizing;
- embedding into a PDF;
- screenshots;
- printing and rescanning.

It is therefore an internal edoc-integrity check, not a general perceptual-image verification method.

---

## 23. Image-format validation

The upload receiver must validate the submitted image before processing.

At minimum:

- confirm expected MIME type;
- decode the image safely;
- reject invalid or oversized payloads;
- enforce reasonable dimensions;
- normalize alpha handling;
- protect against decompression bombs;
- preserve sufficient resolution for legibility;
- avoid browser-dependent rendering;
- use a server-side image library available in the REDCap environment.

The first implementation should determine whether GD, Imagick, or REDCap’s own image utilities provide the most portable path.

Avoid relying on client-provided dimensions or MIME type alone.

---

## 24. Failure behavior

The module must fail closed for a signature upload that it claims to watermark.

If the envelope is invalid or watermark rendering fails:

- do not silently store a clean signature;
- do not create a misleading provenance event;
- return an actionable error to the signature UI where feasible;
- append a technical error log entry.

For project save hooks:

- a binding error must not rewrite an existing binding;
- a scope mismatch must not produce a valid binding;
- a rebinding conflict must result only in an error log;
- exact duplicate processing should remain harmless.

Whether a binding failure should block the main REDCap form save is a separate implementation decision. The first implementation should prefer preserving REDCap data while surfacing the watermark-binding failure clearly, unless a safe and reliable blocking mechanism exists.

---

## 25. Recommended module components

A first code structure could include:

```text
SignatureWatermarkExternalModule.php
src/
    Crypto/
        KeyDerivation.php
        CanonicalJson.php
        EnvelopeSigner.php
        Anchor.php
        BindingMac.php
        ReferenceGenerator.php
    Context/
        PageContext.php
        SavedContext.php
        RecordReference.php
        RepeatContext.php
    Watermark/
        SignatureImage.php
        Renderer.php
        LayoutV1.php
    Storage/
        LogRepository.php
        UploadProvenance.php
        Binding.php
        RecordRename.php
        ErrorEvent.php
    Upload/
        UploadInterceptor.php
        UploadResultCapture.php
    Verification/
        ProjectVerifier.php
        AdminVerifier.php
    Hooks/
        PageRenderHook.php
        RecordSaveHook.php
        RecordRenameHook.php
pages/
    verify-project.php
    verify-admin.php
js/
    signature-watermark.js
css/
    signature-watermark.css
```

The exact structure should follow the conventions of the existing module template and the REDCap External Module framework version targeted.

---

## 26. Hook-discovery tasks for Codex

Before implementing business logic, Codex should inspect the target REDCap version and identify:

1. The page-render hook that can enumerate signature fields on the current form/page.
2. The exact client-side function and iframe form used for scribble and typed signatures.
3. The upload receiver file and the earliest safe point to inspect/replace the image payload.
4. How the field name is transmitted or can be associated with the iframe upload.
5. How to attach the correct per-field envelope when several signature fields exist.
6. How the iframe returns the edoc ID.
7. The point at which the module can reliably append upload provenance containing that edoc ID.
8. The post-save hook that runs after the record and repeat instance are authoritative.
9. How the saved signature field value can be read without relying on stale request values.
10. How new survey records and first-page saves expose the new record ID.
11. How repeat instrument and repeat instance are represented for:
    - classic projects;
    - longitudinal projects;
    - repeating instruments;
    - repeating events.
12. The supported record-rename hook or event.
13. Safe use of database named/advisory locks in REDCap’s database abstraction.
14. Relevant REDCap permissions and CSRF/session facilities.
15. Whether upload processing can be implemented entirely from an EM hook or requires a narrowly scoped interception/override.
16. Differences across supported REDCap versions.

Codex should document every selected hook point and explain why it is reliable.

---

## 27. Initial implementation phases

## Phase 1: technical spike

Goal: prove the upload interception and watermark path.

Deliverables:

- detect one configured signature field;
- attach a signed per-field envelope;
- intercept the iframe upload;
- verify the envelope;
- render a simple server-side watermark;
- store the modified PNG through the normal REDCap path;
- capture the resulting edoc ID;
- append a basic upload provenance log.

No repeat handling or verification UI is required yet.

## Phase 2: save-time binding

Deliverables:

- read the persisted signature edoc after save;
- resolve record, event, instrument, field, and repeat context;
- append a one-time binding;
- implement idempotent duplicate handling;
- implement advisory locking;
- log rebinding conflicts without modifying the original binding.

## Phase 3: full watermark format

Deliverables:

- stable-scope anchor;
- context and capture references;
- deterministic repeated overlay;
- readable footer;
- UTC timestamp;
- final PNG digest;
- format versioning;
- tests across signature sizes and typed signatures.

## Phase 4: difficult REDCap contexts

Deliverables:

- first-page surveys;
- new unsaved records;
- auto-numbering;
- repeating instruments;
- repeating events if applicable;
- multiple signature fields;
- delete/redraw before save;
- abandoned uploads.

## Phase 5: verification

Deliverables:

- project-scoped exact lookup;
- administrator exact lookup;
- anchor recomputation;
- binding MAC validation;
- current-field comparison;
- final edoc digest comparison.

## Phase 6: retention and hardening

Deliverables:

- purge policy for unbound upload provenance;
- record-rename tracking if not implemented earlier; record pseudonyms are
  explicitly out of scope for the first release unless a future external
  correlation workflow requires them;
- structured error reporting;
- configuration UI;
- compatibility testing across REDCap versions;
- security review;
- performance review.

---

## 28. Suggested first-version configuration

System-level settings:

- enable administrator verification page;
- anchor length;
- capture/context reference lengths;
- maximum signature image dimensions;
- logging verbosity;
- optional institutional label or logo;
- supported watermark layout version.

Project-level settings:

- enable module for project;
- unbound upload provenance retention period;
- enable all signature fields or selected fields only;
- watermark opacity;
- footer visibility;
- project verification permission/role requirements;
- optional short public project label;
- fail behavior on upload watermark error.

Per-field selection should use actual signature field metadata, not arbitrary text entry.

---

## 29. Testing matrix

## 29.1 Basic capture

- scribble signature;
- typed signature;
- empty/invalid signature;
- very small signature;
- signature filling most of the canvas;
- transparent background;
- white background;
- high-DPI display.

## 29.2 Multiple fields

- two signature fields on one page;
- redraw only first field;
- redraw both fields;
- save one field and leave one empty;
- verify unique context references;
- verify unique capture references.

## 29.3 Save lifecycle

- upload and save;
- upload, delete, redraw, save;
- upload and abandon page;
- upload and cancel;
- save failure;
- double form submission;
- repeated hook invocation;
- browser back/forward;
- iframe retry.

## 29.4 Records

- existing record;
- new manually named record;
- auto-numbered record;
- record rename;
- record copied through legitimate REDCap mechanisms;
- attempted edoc reuse in another record.

## 29.5 Surveys

- first survey page with no previously exposed record ID;
- multi-page survey;
- return code/resume;
- completed survey;
- abandoned survey;
- public survey link;
- survey queue where relevant.

## 29.6 Longitudinal/repeating

- classic non-longitudinal project;
- longitudinal non-repeating event;
- repeating instrument;
- new repeat instance;
- edit existing repeat instance;
- repeating event if supported;
- multiple signature fields in a repeating instance.

## 29.7 Security

- modify JSON payload without updating HMAC;
- replace envelope from another field;
- replace envelope from another project;
- expired envelope;
- replay envelope;
- assign edoc from Field A to Field B;
- attempt second binding of same edoc;
- concurrent binding attempts;
- tamper with stored binding JSON;
- alter edoc bytes where technically possible;
- malformed or oversized image payload.

## 29.8 Verification

- valid current signature;
- valid historical signature no longer current;
- unbound upload;
- unknown capture reference;
- anchor mismatch;
- binding MAC mismatch;
- file digest mismatch;
- insufficient project permission;
- data-access-group restrictions;
- administrator lookup.

---

## 30. Acceptance criteria for the first usable release

A first usable release should satisfy all of the following:

1. Every newly captured signature in an enabled field is watermarked server-side before edoc storage.
2. No clean signature is silently stored when watermarking fails.
3. The visible image contains:
   - watermark version;
   - stable-scope anchor;
   - context reference;
   - capture reference;
   - UTC capture timestamp.
4. The field name is cryptographically included in the anchor but not visibly printed into the image.
5. Every field has its own signed envelope.
6. Client tampering with the envelope is detected.
7. Multiple signature fields on one page are supported.
8. Typed and drawn signatures follow the same path.
9. New records and new repeat instances can be handled without image replacement.
10. Only the edoc actually persisted in the signature field is bound.
11. An edoc can be bound successfully at most once.
12. Exact duplicate binding processing is harmless.
13. Conflicting rebinding attempts create an error log only.
14. Existing signatures are ignored.
15. Successful bindings are stored append-only in the EM log table.
16. Verification can recompute the stable-scope anchor.
17. Verification can validate the binding MAC and final PNG digest.
18. No dedicated database table is introduced.

---

## 31. Open implementation decisions

The architecture is sufficiently defined to begin coding, but the first implementation still needs to resolve:

1. Exact REDCap hook points for upload interception and post-save binding.
2. How the correct field envelope is attached to each iframe upload.
3. Whether capture references are generated immediately before rendering or after a transport-specific request identifier is known.
4. The exact mechanism for obtaining the edoc ID after normal upload processing.
5. How to make upload provenance creation robust if REDCap’s upload handler terminates or redirects.
6. Advisory-lock support and naming in the target database abstraction.
7. Whether record pseudonyms are included in the first milestone or added after the binding spike.
8. Exact watermark dimensions, opacity, typography, and identifier length.
9. Retention duration for unbound uploads.
10. Whether a save-time binding failure should merely log/display an error or block completion in selected strict configurations.
11. Which REDCap versions will be officially supported.
12. Whether the project verification page should be available to all users with record access or require a specific module permission.

These decisions should be documented in code comments and the module README as they are resolved.

---

## 32. High-level pseudocode

### Page rendering

```php
foreach ($signatureFieldsOnPage as $field) {
    $contextRef = getOrCreateFieldContextReference(
        $projectId,
        $recordReference,
        $eventId,
        $instrument,
        $field
    );

    $payload = [
        'v'           => 1,
        'pid'         => $projectId,
        'event_id'    => $eventId,
        'instrument'  => $instrument,
        'field'       => $field,
        'context_ref' => $contextRef,
        'record_ref'  => $recordReference,
        'issued_at'   => time(),
        'expires_at'  => time() + ENVELOPE_TTL,
        'nonce'       => randomBase64Url()
    ];

    $envelope = signCanonicalPayload($payload, K_envelope);
    exposeEnvelopeToField($field, $envelope);
}
```

### Upload receiver

```php
$envelope = extractEnvelopeFromUploadRequest();
$scope = verifyAndDecodeEnvelope($envelope, K_envelope);

validateProjectEventInstrumentField($scope);
validateSignatureFieldConfiguration($scope);

$anchor = computeAnchor($scope, K_anchor);
$captureRef = generateCaptureReference();

$originalPng = decodeSubmittedSignature();
$watermarkedPng = renderWatermark(
    $originalPng,
    $anchor,
    $scope['context_ref'],
    $captureRef,
    utcNow()
);

replaceSubmittedSignaturePayload($watermarkedPng);

$edocId = continueNormalRedcapUploadAndObtainEdocId();

appendUploadProvenance([
    'capture_ref' => $captureRef,
    'context_ref' => $scope['context_ref'],
    'anchor'      => $anchor,
    'scope'       => $scope,
    'edoc_id'     => $edocId,
    'file_sha256' => sha256($watermarkedPng)
]);
```

### Post-save binding

```php
foreach ($configuredSignatureFieldsInSavedForm as $field) {
    $edocId = readPersistedSignatureEdocId($savedContext, $field);

    if (!$edocId) {
        continue;
    }

    $upload = findUploadProvenanceByEdocId($edocId);

    if (!$upload) {
        // Existing or otherwise non-module signature: ignore unless policy says
        // this should be treated as an error for newly attempted captures.
        continue;
    }

    $binding = buildAuthoritativeBinding(
        $savedContext,
        $field,
        $upload
    );

    withAdvisoryLock("sigwm:bind:$edocId", function () use ($binding) {
        $existing = findSuccessfulBindingByEdocId($binding->edocId);

        if ($existing === null) {
            appendSuccessfulBinding($binding);
            return;
        }

        if ($existing->equals($binding)) {
            return; // idempotent no-op
        }

        appendBindingConflictError($existing, $binding);
    });
}
```

---

## 33. Guiding principle for implementation decisions

Whenever REDCap’s upload and save lifecycle creates ambiguity, use the following rule:

> The immutable image may contain only information that is authoritative at upload time or stable pseudonymous references. The full record and repeat context becomes authoritative only through the first successful append-only edoc binding after save.

This rule should prevent accidental reliance on guessed record IDs, guessed repeat instances, mutable display values, or client-supplied context.
