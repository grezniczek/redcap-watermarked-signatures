<?php

/** @var \DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule $module */

try {
    if (!defined('PROJECT_ID') || !is_numeric(PROJECT_ID)) {
        throw new RuntimeException('Project context is required.');
    }
    $projectId = (int) PROJECT_ID;
    $settings = $module->get_project_settings_state($projectId);
} catch (Throwable $exception) {
    http_response_code(403);
    echo '<div class="alert alert-danger m-4">' . htmlspecialchars(
        $module->framework->tt('settings_access_denied'), // Project design rights are required to configure Watermarked Signatures.
        ENT_QUOTES,
        'UTF-8'
    ) . '</div>';
    return;
}

$saved = false;
$errorKey = null;
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $result = $module->save_project_settings(
        $projectId,
        $_POST,
        $_FILES['custom_background_image'] ?? null
    );
    $settings = $result['state'];
    $saved = $result['ok'];
    $errorKey = $result['error_key'];
}

$escape = function ($value) {
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
};
$errorMessages = array(
    'settings_error_invalid_request' => $module->framework->tt('settings_error_invalid_request'), // The settings request was invalid. Please reload the page and try again.
    'settings_error_retention_days' => $module->framework->tt('settings_error_retention_days'), // Enter a whole-number retention period from 0 to 3650 days.
    'settings_error_public_project_reference' => $module->framework->tt('settings_error_public_project_reference'), // The public project reference must be blank or use 1–30 permitted ASCII characters.
    'settings_error_background_mode' => $module->framework->tt('settings_error_background_mode'), // Choose a valid signature background mode.
    'settings_error_background_rotation' => $module->framework->tt('settings_error_background_rotation'), // Enter a whole-number custom-image rotation from -180 to 180 degrees.
    'settings_error_custom_image_required' => $module->framework->tt('settings_error_custom_image_required'), // Upload a valid custom image before selecting the custom-image background mode.
    'settings_error_image_upload' => $module->framework->tt('settings_error_image_upload'), // The replacement image could not be uploaded.
    'settings_error_image_upload_size' => $module->framework->tt('settings_error_image_upload_size'), // The replacement image must be between 1 byte and 6 MiB.
    'settings_error_image_invalid' => $module->framework->tt('settings_error_image_invalid'), // The replacement image must be a valid PNG with permitted dimensions.
    'settings_error_save' => $module->framework->tt('settings_error_save'), // The project settings could not be saved. Please try again or contact a REDCap administrator.
    'settings_error_validation_unavailable' => $module->framework->tt('settings_error_validation_unavailable') // The changed settings could not be validated. Check your connection and try again.
);
$errorFields = array(
    'settings_error_retention_days' => 'retention_days',
    'settings_error_public_project_reference' => 'public_project_reference',
    'settings_error_background_mode' => 'background_image_mode',
    'settings_error_background_rotation' => 'background_image_rotation',
    'settings_error_custom_image_required' => 'custom_background_image',
    'settings_error_image_upload' => 'custom_background_image',
    'settings_error_image_upload_size' => 'custom_background_image',
    'settings_error_image_invalid' => 'custom_background_image'
);
$fieldErrors = array();
$actionError = null;
if (is_string($errorKey) && isset($errorMessages[$errorKey])) {
    if (isset($errorFields[$errorKey])) {
        $fieldErrors[$errorFields[$errorKey]] = $errorKey;
    } else {
        $actionError = $errorKey;
    }
}

// Keep editable values after a failed POST. The stored state remains available
// separately for the current-image preview and the Discard changes action.
$formValues = array(
    'retention_days' => (string) $settings['retention_days'],
    'public_project_reference' => (string) $settings['public_project_reference'],
    'background_image_mode' => (string) $settings['background_image_mode'],
    'background_image_rotation' => (string) $settings['background_image_rotation']
);
if (!$saved && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    foreach (array_keys($formValues) as $field) {
        if (isset($_POST[$field]) && is_scalar($_POST[$field])) {
            $formValues[$field] = (string) $_POST[$field];
        }
    }
}

$customImage = $settings['custom_image'];
$previewUrl = $customImage['preview_data_url'];
$javascriptDebugSetting = $module->getProjectSetting('javascript-debug');
$javascriptDebug = in_array($javascriptDebugSetting, array(true, 1, '1', 'true'), true);
$redcapLogoUrl = defined('APP_PATH_WEBROOT')
    ? rtrim((string) APP_PATH_WEBROOT, '/') . '/Resources/images/redcap-logo.png'
    : null;
$clientConfig = array(
    'savedValues' => array(
        'retention_days' => (string) $settings['retention_days'],
        'public_project_reference' => (string) $settings['public_project_reference'],
        'background_image_mode' => (string) $settings['background_image_mode'],
        'background_image_rotation' => (string) $settings['background_image_rotation']
    ),
    'validationAction' => \DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule::AJAX_VALIDATE_PROJECT_SETTINGS,
    'maxCustomBackgroundImageUploadBytes' => \DE\RUB\WatermarkedSignaturesExternalModule\Watermark\Renderer::MAX_CUSTOM_BACKGROUND_IMAGE_UPLOAD_BYTES,
    'debug' => $javascriptDebug,
    'redcapLogoUrl' => $redcapLogoUrl
);
$module->framework->initializeJavascriptModuleObject();
$module->framework->tt_transferToJavascriptModuleObject(array(
    'settings_unsaved_changes',
    'settings_validation_unavailable',
    'settings_error_invalid_request',
    'settings_error_retention_days',
    'settings_error_public_project_reference',
    'settings_error_background_mode',
    'settings_error_background_rotation',
    'settings_error_custom_image_required',
    'settings_error_image_upload',
    'settings_error_image_upload_size',
    'settings_error_image_invalid',
    'settings_error_save'
));
?>

<style>
    .sigwm-settings { max-width: 960px; }
    .sigwm-settings h1.projhdr { margin-bottom: .35rem; font-size: 1.3rem; }
    .sigwm-settings-intro { margin-bottom: .65rem; }
    .sigwm-settings-card { padding: .75rem; }
    .sigwm-settings fieldset { min-width: 0; }
    .sigwm-settings fieldset > legend,
    .sigwm-settings-preview-heading { display: block; width: 100%; margin-bottom: .2rem; font-size: 1rem !important; font-weight: 600; }
    .sigwm-settings .form-label { margin-bottom: .15rem; font-size: .8125rem; }
    .sigwm-settings .form-text { max-width: 740px; margin-top: .2rem; font-size: .75rem; line-height: 1.25; }
    .sigwm-settings .form-check { min-height: 1.15rem; margin-bottom: .2rem; font-size: .8125rem; }
    .sigwm-settings .form-range { height: .8rem; }
    .sigwm-settings .invalid-feedback { margin-top: .2rem; font-size: .75rem; }
    .sigwm-settings-preview { overflow: hidden; background: #f5f7f8; }
    .sigwm-settings-preview canvas { display: block; width: 100%; max-width: 460px; height: auto; background: #fff; }
    .sigwm-settings-preview p { max-width: 460px; font-size: .75rem; }
    .sigwm-settings-current-image { overflow-wrap: anywhere; font-size: .75rem; line-height: 1.25; }
    .sigwm-settings-actions { border-top: 1px solid #dee2e6; }
    .sigwm-settings-actions [hidden] { display: none !important; }
</style>

<div class="sigwm-settings mb-4">
    <h1 class="projhdr"><i class="fa-solid fa-sliders me-2"></i><?= $escape($module->framework->tt('settings_page_title')) /* Configure Watermarked Signatures */ ?></h1>
    <p class="sigwm-settings-intro text-muted small"><?= $escape($module->framework->tt('settings_intro')) /* These settings apply to future signature captures in this project. Existing signatures and their provenance are not changed. */ ?></p>

    <form id="sigwm-project-settings-form" method="post" enctype="multipart/form-data" class="card card-body sigwm-settings-card" autocomplete="off" novalidate>
        <input type="hidden" name="redcap_csrf_token" value="<?= $escape($module->getCSRFToken()) ?>">

        <fieldset class="mb-3" data-settings-field="retention_days">
            <legend><?= $escape($module->framework->tt('settings_retention_heading')) /* Unbound upload retention */ ?></legend>
            <label for="sigwm-retention-days" class="form-label fw-semibold"><?= $escape($module->framework->tt('settings_retention_label')) /* Retain unbound upload provenance for days */ ?></label>
            <input id="sigwm-retention-days" class="form-control form-control-sm<?= isset($fieldErrors['retention_days']) ? ' is-invalid' : '' ?>" type="number" name="retention_days" min="0" max="3650" step="1" required value="<?= $escape($formValues['retention_days']) ?>">
            <div class="form-text"><?= $escape($module->framework->tt('settings_retention_help')) /* Enter 0 to retain unbound upload provenance indefinitely. Otherwise enter a whole number from 1 to 3650. */ ?></div>
            <div class="invalid-feedback d-block" data-settings-error="retention_days"<?= isset($fieldErrors['retention_days']) ? '' : ' hidden' ?>><?= isset($fieldErrors['retention_days']) ? $escape($errorMessages[$fieldErrors['retention_days']]) : '' ?></div>
        </fieldset>

        <fieldset class="mb-3" data-settings-field="public_project_reference">
            <legend><?= $escape($module->framework->tt('settings_public_reference_heading')) /* Public project reference */ ?></legend>
            <label for="sigwm-public-reference" class="form-label fw-semibold"><?= $escape($module->framework->tt('settings_public_reference_label')) /* Visible REF: value (optional) */ ?></label>
            <input id="sigwm-public-reference" class="form-control form-control-sm<?= isset($fieldErrors['public_project_reference']) ? ' is-invalid' : '' ?>" type="text" name="public_project_reference" maxlength="30" value="<?= $escape($formValues['public_project_reference']) ?>">
            <div class="form-text"><?= $escape($module->framework->tt('settings_public_reference_help')) /* This value is printed on every future signature image. Use 1–30 ASCII letters, digits, spaces, periods, hyphens, underscores, or slashes. Do not use sensitive information. */ ?></div>
            <div class="invalid-feedback d-block" data-settings-error="public_project_reference"<?= isset($fieldErrors['public_project_reference']) ? '' : ' hidden' ?>><?= isset($fieldErrors['public_project_reference']) ? $escape($errorMessages[$fieldErrors['public_project_reference']]) : '' ?></div>
        </fieldset>

        <fieldset class="mb-3" data-settings-field="background_image_mode">
            <legend><?= $escape($module->framework->tt('settings_background_heading')) /* Signature background image */ ?></legend>
            <p class="form-text mt-0 mb-1"><?= $escape($module->framework->tt('settings_background_help')) /* Choose the optional faint background. The identifier overlay and WM1 footer are always applied. */ ?></p>
            <?php foreach (array(
                'redcap' => $module->framework->tt('settings_background_mode_redcap'), // Use the REDCap logo
                'custom' => $module->framework->tt('settings_background_mode_custom'), // Use the custom image
                'none' => $module->framework->tt('settings_background_mode_none') // Do not use a background image
            ) as $value => $label): ?>
                <div class="form-check">
                    <input id="sigwm-background-<?= $escape($value) ?>" class="form-check-input" type="radio" name="background_image_mode" value="<?= $escape($value) ?>"<?= $formValues['background_image_mode'] === $value ? ' checked' : '' ?>>
                    <label class="form-check-label" for="sigwm-background-<?= $escape($value) ?>"><?= $escape($label) ?></label>
                </div>
            <?php endforeach; ?>
            <div class="invalid-feedback d-block" data-settings-error="background_image_mode"<?= isset($fieldErrors['background_image_mode']) ? '' : ' hidden' ?>><?= isset($fieldErrors['background_image_mode']) ? $escape($errorMessages[$fieldErrors['background_image_mode']]) : '' ?></div>
        </fieldset>

        <div class="row g-3">
            <div class="col-lg-6">
                <fieldset class="h-100">
                    <legend><?= $escape($module->framework->tt('settings_custom_image_heading')) /* Custom background image */ ?></legend>
                    <div data-settings-field="custom_background_image">
                        <label for="sigwm-custom-image" class="form-label fw-semibold"><?= $escape($module->framework->tt('settings_custom_image_label')) /* Upload a replacement PNG (optional) */ ?></label>
                        <input id="sigwm-custom-image" class="form-control form-control-sm<?= isset($fieldErrors['custom_background_image']) ? ' is-invalid' : '' ?>" type="file" name="custom_background_image" accept="image/png,.png">
                        <div class="form-text mb-2"><?= $escape($module->framework->tt('settings_custom_image_help')) /* A replacement image is normalized before storage to at most 512 pixels per side and 1 MiB. Upload PNG files up to 6 MiB; each side must be 16–4096 pixels and the image must contain no more than 12 million pixels. Very wide or tall images that cannot remain at least 16 pixels per side after normalization are rejected. The existing image is retained if you do not choose a replacement. */ ?></div>
                        <div class="invalid-feedback d-block" data-settings-error="custom_background_image"<?= isset($fieldErrors['custom_background_image']) ? '' : ' hidden' ?>><?= isset($fieldErrors['custom_background_image']) ? $escape($errorMessages[$fieldErrors['custom_background_image']]) : '' ?></div>
                    </div>

                    <div data-settings-field="background_image_rotation">
                        <label for="sigwm-background-rotation" class="form-label fw-semibold mt-2"><?= $escape($module->framework->tt('settings_rotation_label')) /* Custom image rotation (degrees) */ ?></label>
                        <input id="sigwm-background-rotation" class="form-range<?= isset($fieldErrors['background_image_rotation']) ? ' is-invalid' : '' ?>" type="range" name="background_image_rotation" min="-180" max="180" step="1" value="<?= $escape($formValues['background_image_rotation']) ?>">
                        <output id="sigwm-background-rotation-output" class="d-inline-block"><code><?= $escape($formValues['background_image_rotation']) ?>°</code></output>
                        <div class="form-text mb-2"><?= $escape($module->framework->tt('settings_rotation_help')) /* Applies only when the custom image is selected. Positive values rotate counterclockwise. Allowed range: -180 to 180. */ ?></div>
                        <div class="invalid-feedback d-block" data-settings-error="background_image_rotation"<?= isset($fieldErrors['background_image_rotation']) ? '' : ' hidden' ?>><?= isset($fieldErrors['background_image_rotation']) ? $escape($errorMessages[$fieldErrors['background_image_rotation']]) : '' ?></div>
                    </div>

                    <div class="sigwm-settings-current-image mt-2">
                        <span class="fw-semibold"><?= $escape($module->framework->tt('settings_current_image')) /* Current stored image */ ?>:</span>
                        <?php if ($customImage['available']): ?>
                            <code><?= $escape($customImage['doc_name']) ?> · <?= $escape($customImage['width']) ?>×<?= $escape($customImage['height']) ?> px · <?= $escape($customImage['sha256']) ?></code>
                        <?php elseif ($customImage['edoc_id'] !== ''): ?>
                            <span class="text-danger"><?= $escape($module->framework->tt('settings_invalid_current_image')) /* A custom image setting exists but its stored file is unavailable or invalid. Upload a replacement before selecting the custom-image mode. */ ?></span>
                        <?php else: ?>
                            <span class="text-muted"><?= $escape($module->framework->tt('settings_no_current_image')) /* No valid custom image is currently stored. */ ?></span>
                        <?php endif; ?>
                    </div>
                </fieldset>
            </div>
            <div class="col-lg-6">
                <section class="h-100">
                    <h2 class="sigwm-settings-preview-heading"><?= $escape($module->framework->tt('settings_preview_heading')) /* Preview */ ?></h2>
                    <div id="sigwm-custom-image-preview-area" class="sigwm-settings-preview border rounded d-flex flex-column align-items-center justify-content-center p-2">
                        <canvas id="sigwm-watermark-preview" width="460" height="158" aria-label="<?= $escape($module->framework->tt('settings_preview_heading')) /* Preview */ ?>"></canvas>
                        <p id="sigwm-custom-image-preview-empty" class="text-muted text-center mb-0 mt-1"<?= $previewUrl === null ? '' : ' hidden' ?>><?= $escape($module->framework->tt('settings_preview_empty')) /* Choose a PNG to preview the custom image. */ ?></p>
                    </div>
                    <p class="form-text mb-0"><?= $escape($module->framework->tt('settings_preview_help')) /* This representative WM1 preview uses a dummy signature and identifier values. It updates when you change the background mode, image, or rotation; the final image uses the actual signature and capture values. */ ?></p>
                </section>
            </div>
        </div>

        <div class="sigwm-settings-actions d-flex flex-wrap align-items-center gap-2 mt-3 pt-2">
            <button type="submit" class="btn btn-primary btn-sm"><i class="fa-solid fa-floppy-disk me-1"></i><?= $escape($module->framework->tt('settings_save')) /* Save project settings */ ?></button>
            <button id="sigwm-settings-discard" type="button" class="btn btn-outline-secondary btn-sm"><i class="fa-solid fa-arrow-rotate-left me-1"></i><?= $escape($module->framework->tt('settings_discard')) /* Discard changes */ ?></button>
            <span id="sigwm-settings-unsaved" class="badge text-bg-warning" hidden><?= $escape($module->framework->tt('settings_unsaved_changes')) /* Unsaved changes */ ?></span>
            <span id="sigwm-settings-action-message" class="small text-danger" aria-live="polite"<?= $actionError === null ? ' hidden' : '' ?>><?= $actionError === null ? '' : $escape($errorMessages[$actionError]) ?></span>
            <?php if ($saved): ?>
                <span class="small text-success"><i class="fa-solid fa-check me-1"></i><?= $escape($module->framework->tt('settings_saved')) /* Project settings saved. */ ?></span>
            <?php endif; ?>
        </div>
    </form>
</div>

<img id="sigwm-custom-image-preview" src="<?= $escape($previewUrl ?? '') ?>" alt="" hidden>
<script src="<?= $escape($module->getUrl('js/ConsoleDebugLogger.js')) ?>"></script>
<script src="<?= $escape($module->getUrl('js/project-settings.js')) ?>"></script>
<script>
    window.WatermarkedSignaturesProjectSettings.init(
        <?= $module->framework->getJavascriptModuleObjectName() ?>,
        <?= json_encode($clientConfig, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>
    );
</script>
