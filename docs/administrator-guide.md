# Watermarked Signatures administrator guide

This guide is for REDCap administrators who configure Watermarked Signatures or
use its Control Center verification page. Project users should use the
[project-user guide](project-user-guide.md).

## Configure a project

1. Make the module available through your institution's normal External Module
   management process, then enable it for the project.
2. In the Online Designer or Data Dictionary, locate each REDCap **Signature**
   or **Enhanced Signature** field that should be watermarked.
3. Add this field annotation:

   ```text
   @WATERMARKED-SIGNATURE
   ```

   To append a field-specific mark to `REF:`, use a simple quoted parameter,
   for example:

   ```text
   @WATERMARKED-SIGNATURE="CONSENT"
   ```

4. Save the field changes and test a new capture. The final image should show a
   watermark and a footer beginning with `WM1`.

The optional field mark must contain 1–16 ASCII letters, digits, spaces,
periods, hyphens, underscores, or slashes. When both values are configured, the
footer uses `REF:PROJECT:FIELD`; with no project reference, it uses
`REF:FIELD`. Malformed, duplicate, or invalid parameters are omitted and logged
without blocking capture. The tag affects only new captures. Existing
signatures, including signatures captured before the tag was added, are
intentionally not modified or given new provenance.

### Project settings

Project designers and REDCap superusers use **Configure Watermarked Signatures** in the project module links to configure future captures. The standard External Module settings dialog contains only the browser-debug option.

| Setting | Recommended use |
|---|---|
| **Retain unbound signature-upload provenance for this many days** | Leave the default of 90 days unless the project needs a different operational investigation period. Use `0` to disable automated cleanup; values above 3650 are capped at 3650 days. This applies only to uploads that never become bound to a saved record. |
| **Public project reference** | Optional visible `REF:` text on future images. Use only a short public identifier (1–20 ASCII letters, digits, spaces, periods, hyphens, underscores, or slashes). A field mark from the action tag adds a second 1–16 character component. Never enter a project title or any sensitive identifier. |
| **Signature background image** | Leave the default REDCap logo, select a custom image, or remove the optional background image. The security-relevant identifier overlay and `WM1` footer are always present. |
| **Custom background image** | Upload a PNG up to 6 MiB. Each side must be 16–4096 pixels and the image may contain at most 12 million pixels. The page normalizes it before storage to no more than 512 pixels per side and 1 MiB. Its aspect ratio must leave at least 16 pixels per side after normalization. Custom-image mode is unavailable until an image is stored or selected for upload. Use **Add image** when no image is stored, or **Replace image** to choose a new one. The page shows its thumbnail, filename, and dimensions. Select **Remove the current stored image** to mark the thumbnail for removal when saved; removal takes precedence over a pending replacement. It only removes the image from the module and does not change existing signature images. The stored image otherwise remains available while the REDCap-logo or no-image mode is selected. |
| **Custom image rotation** | Applies only to a custom image. Choose a whole-number rotation from -180° through 180°; positive values rotate counterclockwise. The page previews the selected image and rotation before saving. |

**Output debug information to the browser console** remains in REDCap's standard External Module settings dialog. Enable it temporarily while diagnosing browser-side behavior, then disable it.

Changing the public project reference, field annotation, or background-image settings does not rewrite existing images. Each new capture records the project and field references plus the selected and applied background profile, including applied rotation; a valid custom-image capture also records the source file's SHA-256. The configuration and project verification pages audit every watermark action tag and show any issue with its field, instrument, and exact cause. If the selected custom image cannot be read or fails validation, the module logs an error and uses the REDCap logo for that capture. The module uses REDCap's normal edoc workflow and does not create a second image store.

## Use Control Center verification

Select **Administrator signature verification** in the Control Center. This
page is available only to REDCap superusers and searches all projects using the
module.

Enter exactly one of the following:

- the complete capture-reference suffix printed after `S:` in an image footer;
  or
- a positive numeric edoc ID.

The lookup is exact; it is not a listing or a partial search. It verifies the
stored REDCap edoc, rather than a separately uploaded image or screenshot.

The result includes integrity checks, authorized metadata, and technical log
history. It does not display image bytes, signed-envelope nonces, raw log
payloads, or binding MAC values.

### e-Consent IP diagnostic

For a signature uploaded to an e-Consent-enabled survey, the module snapshots
the system-level `pdf_econsent_system_ip` setting at upload time. When that
setting is enabled, it encrypts the upload-time IP in the provenance payload
and binds the ciphertext, capture status, and survey identity with a dedicated
MAC. On verification, it compares the restored upload-time value with REDCap's
IP in the matching stored e-Consent PDF archive row.

Treat a mismatch as a forensic warning, not a signature-integrity failure. A
comparison can be **not tested** because capture was disabled at the time, the
upload-time IP was unavailable, or REDCap has no usable stored e-Consent IP.
The Control Center page shows raw IP values only when the viewer is a superuser
and the Database Query Tool is enabled. In every other module-log and project
diagnostic view, the retained address remains encrypted or is omitted.

## Triage verification results

| Result | Administrator response |
|---|---|
| **Valid and current** | The stored file, binding, scope, and current field value agree. No follow-up is normally needed. |
| **Valid historical signature** | Review whether a later redraw, replacement, field clear, or record lifecycle event explains why the field no longer contains this edoc. |
| **Upload not bound** | Review whether the form/survey was abandoned or save failed. The capture is retained only according to the project's unbound-provenance setting. |
| **Verification failed** | Preserve the capture reference and review the check failures and technical history. Treat this as an integrity incident until resolved. |
| **Verification incomplete** | Check edoc storage availability and the current record/field. Retry after correcting an operational storage or record-access issue. |
| **Not found** | Confirm the full reference or numeric edoc ID. A pre-module signature will not have module provenance. |

Record renames do not invalidate a binding. The module retains rename history
and verification uses REDCap's current record identity for the live field check.

## Review technical history

The Control Center result can include binding, rename, and error events relevant
to the resolved edoc. Use the timestamp, actor, project, record, and technical
message to correlate with the REDCap audit trail.

Two upload-provenance diagnostics deserve particular attention:

- `sigwm_error_upload_provenance_response`: REDCap reported a successful upload,
  but the module could not recognize the final edoc ID in the upload response.
  The image may exist without module upload provenance, so it will not become a
  normal bound signature.
- `sigwm_error_upload_provenance_logging`: REDCap created the edoc, but the
  normal `sigwm_upload` provenance entry could not be written. The diagnostic
  retains safe capture context where logging remained available.

If either event appears, retain the capture reference, edoc ID when present,
project, field, and time before investigating. Do not edit module log rows to
make a result appear valid.

An e-Consent-IP mismatch should be correlated with the REDCap survey audit
trail and the timing of the signature upload and survey completion. Do not
interpret it by itself as evidence that the signature or consent is invalid.

## Operational and privacy boundaries

- Successful bindings, record-rename history, and serious error events are
  retained. Only unbound upload provenance is eligible for scheduled cleanup.
- The `S:` capture reference is a high-entropy exact lookup identifier. It is
  printed on the image, so handle exported images according to local policy.
- `TS:` is a server-generated image-capture timestamp, not proof of signer
  identity or a qualified signing time.
- e-Consent upload IP evidence is encrypted in module-log payloads and is
  restorable only by the module with the installation secret. Do not copy or
  disclose it outside an approved forensic process.
- This module is an audit aid and does not independently satisfy legal,
  institutional, or electronic-consent requirements.

See the [main documentation](../README.md) for the shared overview.
