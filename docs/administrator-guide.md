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

4. Save the field changes and test a new capture. The final image should show a
   watermark and a footer beginning with `WM1`.

The tag has no parameters and affects only new captures. Existing signatures,
including signatures captured before the tag was added, are intentionally not
modified or given new provenance.

### Project settings

| Setting | Recommended use |
|---|---|
| **Retain unbound signature-upload provenance for this many days** | Leave the default of 90 days unless the project needs a different operational investigation period. Use `0` to disable automated cleanup; values above 3650 are capped at 3650 days. This applies only to uploads that never become bound to a saved record. |
| **Public project reference** | Optional visible `REF:` text on future images. Use only a short public identifier (1–30 ASCII letters, digits, spaces, periods, hyphens, underscores, or slashes). Never enter a project title or any sensitive identifier. |
| **Signature background image** | Leave the default REDCap logo, select a custom image, or remove the optional background image. The security-relevant identifier overlay and `WM1` footer are always present. |
| **Custom signature background image** | Upload a PNG that is at least 16×16 and at most 512×512 pixels, and no larger than 1 MiB. It is retained even while the REDCap-logo or no-image mode is selected; switch the radio setting to use it. |
| **Output debug information to the browser console** | Enable temporarily while diagnosing browser-side behavior, then disable it. |

Changing the public project reference or background-image settings does not
rewrite existing images. Each new capture records the selected and applied
background profile; a valid custom-image capture also records the source file's
SHA-256. If the selected custom image cannot be read or fails validation, the
module logs an error and uses the REDCap logo for that capture. The module uses
REDCap's normal edoc workflow and does not create a second image store.

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

## Operational and privacy boundaries

- Successful bindings, record-rename history, and serious error events are
  retained. Only unbound upload provenance is eligible for scheduled cleanup.
- The `S:` capture reference is a high-entropy exact lookup identifier. It is
  printed on the image, so handle exported images according to local policy.
- `TS:` is a server-generated image-capture timestamp, not proof of signer
  identity or a qualified signing time.
- This module is an audit aid and does not independently satisfy legal,
  institutional, or electronic-consent requirements.

See the [main documentation](../README.md) for the shared overview and the
[technical design](../DEV_DOCS/verification_contract.md) for implementation
details.
