# Proposed REDCap External Module hooks for trusted signature uploads

## Purpose

Watermarked Signatures currently uses three deliberate workarounds to reach
otherwise unavailable lifecycle points:

1. it wraps the browser-global `filePopUp()` function to add a field-specific
   signed envelope to REDCap's shared upload form;
2. it uses `redcap_every_page_before_render` to identify the signature upload
   request and replaces `$_POST['myfile_base64']` before REDCap creates the
   edoc; and
3. it holds an output buffer open and parses REDCap's `stopUpload(...)`
   JavaScript response to learn the edoc ID.

It also observes three separate record-rename paths: data-entry save, the
Record Home dialog, and the API. These techniques work against REDCap 17.3.0,
but they rely on internal request shapes, JavaScript names, and response text.
The hooks below would make the same work explicit, supported, and useful to
other modules that need to process signature images or audit record renames.

The proposals are intentionally narrow. They do not create a generic way for a
module to rewrite arbitrary file uploads, alter a normal record save, or read
signature content after it has been stored.

## Conventions used by these proposals

The proposed names follow the External Module convention of a
`redcap_module_` prefix. Their first argument is always `$project_id`, allowing
the External Modules framework to discover enabled project modules in the same
way as existing module hooks.

The proposed contracts also follow two existing REDCap patterns:

- `redcap_module_dashboard_before_render` passes mutable dashboard title and
  body values by reference. It is the precedent for the client configuration
  and pre-storage image parameters below.
- `redcap_module_api_before` and `redcap_module_randomize_record` demonstrate
  that a hook may affect core control flow. For a multi-module transform,
  however, a by-reference error list composes more safely than one return value
  that can be supplied by only one module.

| Existing hook | Core pattern | Relevance to these proposals |
|---|---|---|
| `redcap_module_dashboard_before_render` | `Classes/ProjectDashboards.php` calls `ExternalModules::callHook()` with `&$dash['title']` and `&$dash['body']`. | REDCap already supports mutable values shared across enabled modules. |
| `redcap_module_api_before` | `API/index.php` calls the hook after API authentication/context setup and treats a non-null return as an error response. | A hook can run at a narrow, trusted lifecycle point and affect control flow. |
| `redcap_module_randomize_record` | `Classes/Randomization.php` documents a small set of return values before it performs the allocation. | A hook contract needs an explicit, core-owned interpretation of any outcome. |
| `redcap_module_dashboard_after_render` | `Classes/ProjectDashboards.php` calls it only after REDCap has rendered the dashboard. | The post-upload and post-rename proposals are similarly action-only notifications. |

All hooks below are External Module hooks, not legacy `redcap_*` Hooks.php
functions. They are called through `ExternalModules::callHook()` and should be
listed by the External Module hook-discovery UI in the normal way.

The following terms are used throughout:

- **signature upload** means a field whose validation type is `signature` or
  `enhanced_signature`, submitted as the PNG base64 payload used by REDCap's
  signature UI;
- **capture origin** is `data_entry` or `survey`;
- **record** is the record value present in the upload request. It may be
  `null` or provisional for a new record, and is never an authoritative
  substitute for `redcap_save_record` context; and
- **request fields** are untrusted scalar POST values. They are provided so a
  module can read its own signed transport token. They are not a source of
  authoritative project, field, event, user, or record context.

## Upload lifecycle enabled by the proposals

```text
Page render
  └─ redcap_module_signature_upload_client_config
       └─ REDCap filePopUp() adds the configured hidden inputs for this field

Signature POST
  └─ redcap_module_signature_upload_before
       └─ validates/transforms the decoded PNG or appends a fail-closed error
  └─ Files::uploadFile()
  └─ DataEntry::addEdocDataMapping()
  └─ redcap_module_signature_upload_after
       └─ receives the authoritative edoc ID and final PNG digest
  └─ REDCap returns stopUpload(...)

Successful form/survey save
  └─ existing redcap_save_record
       └─ remains the authoritative record/field binding point
```

The existing `redcap_save_record` hook is sufficient for authoritative
post-save binding. No additional save hook is proposed here.

---

## 1. `redcap_module_signature_upload_client_config`

### Problem addressed

The signature dialog uses one browser-side form for every field. There is no
supported way for a module to declare field-specific hidden inputs for the
next signature upload. Watermarked Signatures consequently replaces the global
`filePopUp()` function and must remove stale inputs itself.

### Proposed hook

```php
public function redcap_module_signature_upload_client_config(
    int $project_id,
    ?string $record,
    string $instrument,
    int $event_id,
    ?int $group_id,
    int $repeat_instance,
    string $capture_origin,
    array $signature_fields,
    array &$hidden_inputs_by_field
)
```

`$hidden_inputs_by_field` has this deliberately limited shape:

```php
[
    'signature_field_name' => [
        'module_specific_input_name' => 'opaque transport value',
    ],
]
```

For example, this module would assign its signed envelope as follows:

```php
$hidden_inputs_by_field['participant_signature']['sigwm_envelope'] = $envelope;
```

### Arguments

| Argument | Meaning |
|---|---|
| `$project_id` | Current project ID. |
| `$record` | Current record if known; may be `null` for a new record or first public-survey page. |
| `$instrument` | Current instrument's unique name. |
| `$event_id` | Current event ID. |
| `$group_id` | Current record/user data-access-group context, if available. |
| `$repeat_instance` | Current repeat instance, with `1` for non-repeating contexts. |
| `$capture_origin` | `data_entry` or `survey`; REDCap derives it, rather than accepting a browser value. |
| `$signature_fields` | Valid signature/enhanced-signature field names on the current instrument. |
| `&$hidden_inputs_by_field` | Field-to-hidden-input map to be emitted by REDCap and consumed by its upload dialog. |

### Insertion place

Call the hook during data-entry and survey page rendering after REDCap has
resolved the instrument, event, repeat context, and renderable signature
fields, but before it emits the file-upload dialog configuration and
`DataEntrySurveyCommon.js` setup for the page.

REDCap should serialize the resulting map into a namespaced client
configuration. Its built-in `filePopUp(field_name, ...)` should then:

1. remove all module-managed hidden inputs from the shared upload form;
2. if `field_name` is a signature field, append the scalar inputs configured
   for that field; and
3. leave the form free of module-managed inputs for an ordinary file upload.

This must be implemented by REDCap itself, rather than by calling module JavaScript
at dialog-open time. It retains REDCap ownership of the shared form and ensures
that a prior field's values cannot accompany another field's upload.

### Documentation text

**Summary:** Allows an External Module to provide field-specific, scalar hidden
inputs that REDCap will attach to the next signature upload from the current
data-entry or survey page.

**Description:** The hook runs while REDCap renders a page containing one or
more signature fields. Add values to `$hidden_inputs_by_field` only for fields
listed in `$signature_fields`. REDCap serializes the values for its own
`filePopUp()` implementation, which removes previously managed values and
attaches the matching field's values immediately before upload. Values are
visible to the browser and must not contain secrets. A signed or otherwise
integrity-protected opaque transport value is appropriate.

**Return:** Nothing. Modify `$hidden_inputs_by_field` by reference.

**Restrictions:** Input names must be valid HTML form-control names; values
must be scalar strings within a documented size limit. REDCap should reject
invalid entries rather than rendering them. Modules must use names that are
unique to their prefix. REDCap does not consider these values trusted.

**Location of execution:** During data-entry and survey page rendering, after
the signature field list and page context are known and before the built-in
signature upload dialog can be opened.

---

## 2. `redcap_module_signature_upload_before`

### Problem addressed

There is no signature-specific server hook between REDCap's request/context
validation and the point at which `DataEntry/file_upload.php` writes the
base64-decoded PNG to a temporary file. Using the broad
`redcap_every_page_before_render` hook forces a module to recognise an
implementation-specific request and mutate `$_POST` directly.

### Proposed hook

```php
public function redcap_module_signature_upload_before(
    int $project_id,
    ?string $record,
    string $instrument,
    string $field_name,
    int $event_id,
    ?int $group_id,
    int $repeat_instance,
    ?string $survey_hash,
    ?int $response_id,
    string $capture_origin,
    string $signature_type,
    string &$png,
    array $request_fields,
    array &$errors
)
```

`$signature_type` is `signature` or `enhanced_signature`. `$png` is the
decoded PNG byte string; it is not base64 text. A module may replace it with a
complete new PNG. To abort storage, it appends a safe diagnostic entry to
`$errors`, for example:

```php
$errors[] = [
    'message' => 'The signature image could not be processed.',
    'module' => 'my_external_module',
];
```

### Arguments

| Argument | Meaning |
|---|---|
| `$project_id`, `$record`, `$instrument`, `$field_name`, `$event_id`, `$group_id`, `$repeat_instance`, `$survey_hash`, `$response_id`, `$capture_origin` | Trusted REDCap request context, with the record caveat defined above. These mirror the relevant data-entry/survey context arguments where available. |
| `$signature_type` | `signature` or `enhanced_signature`. |
| `&$png` | Decoded candidate PNG bytes. Changes become the bytes REDCap stores if no hook appends an error. |
| `$request_fields` | Copy of scalar POST values excluding the raw signature image. It may contain module transport values and is untrusted. |
| `&$errors` | Initially an empty list. A non-empty list prevents temporary-file creation and edoc storage. |

### Insertion place

In `DataEntry/file_upload.php`, insert this hook only for a validated signature
field, after all of the following are true:

1. `Config/init_project.php` has initialized project, authentication/survey,
   CSRF, metadata, and event context;
2. REDCap has validated the posted field, its file type, and event; and
3. REDCap has decoded `myfile_base64` into a non-empty PNG byte string.

Call it immediately before REDCap creates the temporary PNG file and before
`Files::uploadFile()`. If `$errors` is non-empty afterward, return REDCap's
ordinary upload-failure response and do not create an edoc. The normal error
response must not expose a raw module exception or an untrusted `$errors`
value.

### Documentation text

**Summary:** Allows an External Module to validate or transform a candidate
signature PNG before REDCap stores it as an edoc.

**Description:** This hook is called only for `signature` and
`enhanced_signature` field uploads after REDCap has established request
context, but before it writes the temporary file or calls `Files::uploadFile()`.
The PNG bytes are supplied by reference so that a module may replace the image.
Appending any entry to `$errors` cancels the upload before storage. Modules
must preserve valid PNG content when modifying `$png` and must not write to the
HTTP response.

**Return:** Nothing. Modify `$png` and/or append to `$errors` by reference.

**Ordering:** If more than one enabled module implements this hook, modules run
in REDCap's normal enabled-module order. Each module receives the image output
from preceding modules. An error from any module makes the upload fail; modules
must not remove existing error entries.

**Location of execution:** In `DataEntry/file_upload.php`, after signature
request validation and base64 decoding, and immediately before temporary-file
and edoc creation.

---

## 3. `redcap_module_signature_upload_after`

### Problem addressed

The edoc ID is authoritative only after `Files::uploadFile()` succeeds. The
current module must parse REDCap's later `stopUpload(...)` response from an
output buffer to obtain it. That makes a provenance record depend on emitted
JavaScript rather than a server-side lifecycle contract.

### Proposed hook

```php
public function redcap_module_signature_upload_after(
    int $project_id,
    ?string $record,
    string $instrument,
    string $field_name,
    int $event_id,
    ?int $group_id,
    int $repeat_instance,
    ?string $survey_hash,
    ?int $response_id,
    string $capture_origin,
    string $signature_type,
    int $edoc_id,
    int $file_size,
    string $file_sha256,
    array $request_fields
)
```

### Arguments

| Argument | Meaning |
|---|---|
| Context arguments through `$signature_type` | The same trusted context as `redcap_module_signature_upload_before`. |
| `$edoc_id` | The positive edoc ID returned by `Files::uploadFile()` for this upload. |
| `$file_size` | Size in bytes of the final PNG passed to `Files::uploadFile()`. |
| `$file_sha256` | Lowercase SHA-256 digest of those final PNG bytes, computed by REDCap after all pre-storage hooks have run. |
| `$request_fields` | Same untrusted scalar POST-value copy as the before hook. |

### Insertion place

Call this action hook only after all of the following have succeeded:

1. `Files::uploadFile()` has returned a positive edoc ID;
2. REDCap has completed its normal `DataEntry::addEdocDataMapping()` call; and
3. the final file size and SHA-256 digest are known.

It must run before REDCap prints its `stopUpload(...)` response. It must not be
called for an upload error, a zero edoc ID, or a non-signature file upload.

### Documentation text

**Summary:** Notifies an External Module that REDCap successfully stored a
signature PNG and assigned its edoc ID.

**Description:** This is an action-only callback for durable audit/provenance
work that requires the final edoc ID. It runs after REDCap has stored and
mapped the edoc, but before the iframe response is generated. The ID, byte
count, and SHA-256 digest describe the exact PNG stored by REDCap after all
`redcap_module_signature_upload_before` transformations. The hook does not
allow a module to alter the edoc, its data mapping, or the upload response.

**Return:** Nothing. Modules must not emit output, modify arguments, or expect
an exception to undo the already stored edoc. A module should log and handle
its own non-critical provenance failure.

**Location of execution:** In `DataEntry/file_upload.php`, after successful
edoc storage and `DataEntry::addEdocDataMapping()`, before REDCap emits the
successful upload response.

---

## 4. `redcap_module_record_rename_after`

### Problem addressed

REDCap 17.3.0 has no External Module callback for a successful record rename.
The module therefore infers completion from `__old_id__` during a save, parses
the Record Home controller response, and separately observes the API response.
Those paths are difficult to keep correct as REDCap evolves.

### Proposed hook

```php
public function redcap_module_record_rename_after(
    int $project_id,
    string $old_record,
    string $new_record,
    ?int $arm_number,
    string $rename_origin,
    ?string $username
)
```

`$rename_origin` is one of:

- `data_entry_form_save`;
- `data_entry_record_home`;
- `api`; or
- `programmatic` for a supported server-side caller that cannot supply a more
  specific origin.

`$arm_number` is `null` when the rename applies across all applicable arms and
otherwise identifies the arm whose record values were renamed.

### Arguments

| Argument | Meaning |
|---|---|
| `$project_id` | Project containing the renamed record. |
| `$old_record` | Record identifier before the successful rename. |
| `$new_record` | Final canonical record identifier after the successful rename. |
| `$arm_number` | Affected arm number, or `null` for a cross-arm rename. |
| `$rename_origin` | Trusted route category from the fixed list above. |
| `$username` | Authenticated REDCap username, or `null` for a context with no username. It is audit metadata, not the identity of a signature signer. |

### Insertion place

The hook must be emitted exactly once for each successful logical rename, after
all core record-ID updates have completed, including the update to the External
Module log table. It must not be inserted directly into
`DataEntry::changeRecordId()`: `REDCap::renameRecord()` can invoke that method
more than once when it handles multiple arms.

Instead, REDCap should centralize a top-level rename completion notifier and
invoke it after success from:

1. the data-entry form save path after its `DataEntry::changeRecordId()` call;
2. `DataEntryController::renameRecord()` after its successful Record Home
   rename; and
3. `REDCap::renameRecord()` after every requested arm has been renamed
   successfully, including the API route that calls this method.

The callback is observational: it is not a validation hook and cannot cancel
or roll back a completed rename.

### Documentation text

**Summary:** Notifies an External Module after REDCap has successfully renamed
a record.

**Description:** The hook runs once after the complete REDCap rename operation
has succeeded and all REDCap-maintained record references, including External
Module log-table indexed record values, use the final record identifier. It
provides the previous and current identifiers, the scope of the rename, a
trusted route category, and nullable operator metadata. It does not run for a
failed, rejected, or no-op rename.

**Return:** Nothing. Modules must treat the rename as complete and must not
attempt to cancel it by returning a value.

**Location of execution:** Immediately after a top-level data-entry, Record
Home, API, or programmatic rename finishes successfully; never once per
internal table update or per internal arm-specific helper call.

---

## Implementation and compatibility notes

1. The four hooks should be additive. Existing page, upload, save, and API
   hooks must keep their current behavior.
2. REDCap should document the new hooks alongside existing External Module
   hooks and include them in the module manager's hook list.
3. The upload hooks should be covered by tests for data-entry and public survey
   requests, new and existing records, repeating instruments/events, multiple
   signature fields, failure before storage, and a successful callback with
   the final edoc ID and digest.
4. The rename hook should be tested for the data-entry form, Record Home, API,
   single-arm and multi-arm scopes, failure/no-op paths, and the guarantee of
   one callback per logical rename.
5. These hooks do not eliminate the need for an application-level signed
   envelope. The browser remains untrusted; the client configuration hook only
   provides reliable transport for a module's own integrity-protected value.

For this module, adoption would remove the `filePopUp()` replacement, direct
`$_POST` mutation from a broad every-page hook, response-buffer parsing, and
route-specific record-rename response observation. The existing
`redcap_save_record` binding logic would remain unchanged.
