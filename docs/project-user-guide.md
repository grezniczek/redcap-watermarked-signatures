# Capture and verify watermarked signatures

Use this guide when you work in a REDCap project that has **Watermarked
Signatures** enabled. For project configuration and system-level investigation,
see the [administrator guide](administrator-guide.md).

## Capture a signature

For a field configured by the project administrator, use the normal REDCap
signature dialog:

1. Open the form or survey.
2. Draw or replace the signature.
3. Submit the form or survey successfully.

The module adds no extra confirmation step. It securely creates the watermark
on the server before REDCap stores the final PNG.

After capture, the signature image has a watermark overlay and a footer such as:

```text
WM1 S:5622-9F1F-AHCA-K A:ABCD-1234-EFGH-5678 C:7JKM-9NPQ-RSTV-2
TS:2026-08-09T12:34:56.789Z
```

Depending on the project configuration, the signature may also have a faint
repeated background image. It does not change the identifier overlay or footer.

The value after `S:` is the **capture reference**. Keep the complete value when
you need someone to verify an exported image. `TS:` is a server-generated UTC
capture timestamp; it does not identify the signer or establish a qualified
electronic-signature time.

If the form is not successfully submitted after upload, the capture cannot be
bound to a record. Do not assume that an image uploaded in an abandoned form is
the saved signature.

## Verify a signature in this project

1. Select **Verify watermarked signature** from the project menu.
2. Enter the complete value printed after `S:` in the image footer.
3. Select **Verify**.

The lookup is exact. It checks the signature stored by REDCap; it does not
inspect a screenshot or a different image file. The `S:` prefix is already
shown beside the input, so enter only the remainder of the capture reference.

The link is available only to users who can view at least one instrument with a
configured signature field. Results are further limited by your form rights and
Data Access Group (DAG) membership. A missing link or a **Not available**
result does not confirm that a capture does not exist.

## Understand the result

| Result | Meaning | What to do |
|---|---|---|
| **Valid and current** | The stored file and binding checks pass, and the signature is still the field's current value. | No action is normally needed. |
| **Valid historical signature** | The stored file and binding checks pass, but the field was later changed or cleared. | Confirm whether the replacement was expected. |
| **Upload not bound** | REDCap recorded the capture, but no successful form save bound it to a record. | Check whether the form or survey was abandoned or failed to save. |
| **Verification failed** | An integrity check failed. | Do not treat the signature as verified. Preserve the capture reference and contact a REDCap administrator. |
| **Verification incomplete** | REDCap could not read the stored file or the current field value needed for a conclusion. | Retry later or ask an administrator to investigate file storage and record access. |
| **Not found** | No provenance matches the exact reference in your permitted scope. | Recheck every character of the capture reference and confirm the project. |
| **Not available** | The reference is outside your permitted project, form, or DAG scope. | Use a suitably authorized project user or ask an administrator. |

The page may show a link to the bound field when your rights permit it.

## If the signature cannot be securely watermarked

Refresh the form or survey page, then capture the signature again. The module
does not allow REDCap to save an unwatermarked signature when it cannot securely
apply the watermark. If the problem happens again, give a project administrator
the project, instrument, field, and approximate time of the attempt. Do not try
to work around the message by uploading the image to an ordinary file field.

## Privacy reminders

The watermark remains visible in exports and screenshots. Treat the capture
reference and any visible `REF:` project reference according to the project's
data-handling policy. The module verifies REDCap's stored file and does not
return signature image bytes through the verification page.

For the full module overview, see the [main documentation](../README.md).
