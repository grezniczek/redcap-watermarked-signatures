# Add External Module hooks for signature uploads and record renames

## Summary

This PR adds four External Module lifecycle hooks. Three cover a signature field's path from page rendering through edoc storage; the fourth reports a completed record rename. They give modules supported call points for field-specific upload metadata, server-side image processing, provenance logging, and rename auditing.

## Hooks

| Hook | When it runs | Module contract |
| --- | --- | --- |
| `redcap_module_signature_upload_client_config` | While rendering a data-entry or survey page with signature fields | Receives the instrument, event, record/repeat context, capture origin, and signature field list. Modules add field-specific hidden input values by reference. REDCap filters names and UTF-8 string values, serializes the map, and attaches only the selected field's inputs when its upload dialog opens. |
| `redcap_module_signature_upload_before` | After REDCap decodes a signature or enhanced-signature upload, before writing a temporary file | Receives REDCap's upload context, untrusted scalar request fields, and decoded image bytes by reference. Modules may replace the PNG; appending to the shared error list cancels storage with REDCap's ordinary upload-failure response. |
| `redcap_module_signature_upload_after` | After `Files::uploadFile()` succeeds and REDCap adds the edoc data mapping | Reports the final edoc ID, byte count, and SHA-256 digest of the image after all pre-storage transforms. This is an action-only callback before REDCap emits the upload response. |
| `redcap_module_record_rename_after` | After a successful top-level rename | Reports old and final record IDs, affected arm (or `null` for cross-arm scope), origin (`data_entry_form_save`, `data_entry_record_home`, `api`, or `programmatic`), and nullable username. It runs once per logical rename, after core updates including the External Module log record index. |

## Implementation notes

- The upload hooks apply only to `signature` and `enhanced_signature` fields. Normal file uploads retain their existing path. The page hook uses REDCap's shared `filePopUp()` form and clears module-managed inputs before adding the current field's values, so one field's metadata cannot carry into another upload.
- Browser-supplied hidden inputs and other request fields remain untrusted. Modules can use them to transport an integrity-protected token, while the server hook supplies the resolved project, instrument, field, event, repeat, survey, and capture context. A record may be unknown until form or survey save; `redcap_save_record` remains the authoritative binding point.
- The rename notification sits at the data-entry save, Record Home, and `REDCap::renameRecord()` completion paths rather than inside `DataEntry::changeRecordId()`, which may run once per arm. Failed and no-op renames do not notify modules. The callback cannot undo a completed rename.

## Verification

The branch includes PHP tests for signature field discovery, client input filtering, and scalar request-field extraction, plus a JavaScript test covering field switching and cleanup of managed inputs. The four hook call sites and rename origins were checked against the current REDCap branch.
