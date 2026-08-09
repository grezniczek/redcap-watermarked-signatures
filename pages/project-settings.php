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
    'settings_error_save' => $module->framework->tt('settings_error_save') // The project settings could not be saved. Please try again or contact a REDCap administrator.
);
$customImage = $settings['custom_image'];
$mode = $settings['background_image_mode'];
$previewUrl = $customImage['preview_data_url'];
?>

<style>
    .sigwm-settings { max-width: 960px; }
    .sigwm-settings .card-body { padding: 1.25rem; }
    .sigwm-settings .form-text { max-width: 740px; }
    .sigwm-settings-preview { min-height: 250px; overflow: hidden; background: #f5f7f8; }
    .sigwm-settings-preview img { display: block; max-width: 360px; max-height: 210px; object-fit: contain; transition: transform .12s ease-out; }
    .sigwm-settings-preview p { max-width: 360px; }
    .sigwm-settings-current-image { overflow-wrap: anywhere; }
</style>

<div class="sigwm-settings mb-5">
    <h1 class="projhdr"><i class="fa-solid fa-sliders me-2"></i><?= $escape($module->framework->tt('settings_page_title')) /* Configure Watermarked Signatures */ ?></h1>
    <p><?= $escape($module->framework->tt('settings_intro')) /* These settings apply to future signature captures in this project. Existing signatures and their provenance are not changed. */ ?></p>

    <?php if ($saved): ?>
        <div class="alert alert-success"><?= $escape($module->framework->tt('settings_saved')) /* Project settings saved. */ ?></div>
    <?php elseif (is_string($errorKey) && isset($errorMessages[$errorKey])): ?>
        <div class="alert alert-danger"><?= $escape($errorMessages[$errorKey]) ?></div>
    <?php endif; ?>

    <form method="post" enctype="multipart/form-data" class="card card-body" autocomplete="off">
        <input type="hidden" name="redcap_csrf_token" value="<?= $escape($module->getCSRFToken()) ?>">

        <fieldset class="mb-4">
            <legend class="fs-5 mb-2"><?= $escape($module->framework->tt('settings_retention_heading')) /* Unbound upload retention */ ?></legend>
            <label for="sigwm-retention-days" class="form-label fw-bold"><?= $escape($module->framework->tt('settings_retention_label')) /* Retain unbound upload provenance for days */ ?></label>
            <input id="sigwm-retention-days" class="form-control" type="number" name="retention_days" min="0" max="3650" step="1" required value="<?= $escape($settings['retention_days']) ?>">
            <div class="form-text"><?= $escape($module->framework->tt('settings_retention_help')) /* Enter 0 to retain unbound upload provenance indefinitely. Otherwise enter a whole number from 1 to 3650. */ ?></div>
        </fieldset>

        <fieldset class="mb-4">
            <legend class="fs-5 mb-2"><?= $escape($module->framework->tt('settings_public_reference_heading')) /* Public project reference */ ?></legend>
            <label for="sigwm-public-reference" class="form-label fw-bold"><?= $escape($module->framework->tt('settings_public_reference_label')) /* Visible REF: value (optional) */ ?></label>
            <input id="sigwm-public-reference" class="form-control" type="text" name="public_project_reference" maxlength="30" value="<?= $escape($settings['public_project_reference']) ?>">
            <div class="form-text"><?= $escape($module->framework->tt('settings_public_reference_help')) /* This value is printed on every future signature image. Use 1–30 ASCII letters, digits, spaces, periods, hyphens, underscores, or slashes. Do not use sensitive information. */ ?></div>
        </fieldset>

        <fieldset class="mb-4">
            <legend class="fs-5 mb-2"><?= $escape($module->framework->tt('settings_background_heading')) /* Signature background image */ ?></legend>
            <p class="form-text mt-0 mb-2"><?= $escape($module->framework->tt('settings_background_help')) /* Choose the optional faint background. The identifier overlay and WM1 footer are always applied. */ ?></p>
            <?php foreach (array(
                'redcap' => $module->framework->tt('settings_background_mode_redcap'), // Use the REDCap logo
                'custom' => $module->framework->tt('settings_background_mode_custom'), // Use the custom image
                'none' => $module->framework->tt('settings_background_mode_none') // Do not use a background image
            ) as $value => $label): ?>
                <div class="form-check mb-1">
                    <input id="sigwm-background-<?= $escape($value) ?>" class="form-check-input" type="radio" name="background_image_mode" value="<?= $escape($value) ?>"<?= $mode === $value ? ' checked' : '' ?>>
                    <label class="form-check-label" for="sigwm-background-<?= $escape($value) ?>"><?= $escape($label) ?></label>
                </div>
            <?php endforeach; ?>
        </fieldset>

        <div class="row g-4 mb-2">
            <div class="col-lg-6">
                <fieldset class="h-100">
                    <legend class="fs-5 mb-2"><?= $escape($module->framework->tt('settings_custom_image_heading')) /* Custom background image */ ?></legend>
                    <label for="sigwm-custom-image" class="form-label fw-bold"><?= $escape($module->framework->tt('settings_custom_image_label')) /* Upload a replacement PNG (optional) */ ?></label>
                    <input id="sigwm-custom-image" class="form-control" type="file" name="custom_background_image" accept="image/png,.png">
                    <div class="form-text mb-3"><?= $escape($module->framework->tt('settings_custom_image_help')) /* A replacement image is normalized before storage to at most 512 pixels per side and 1 MiB. Upload PNG files up to 6 MiB, with dimensions from 16×16 to 4096×4096 pixels. The existing image is retained if you do not choose a replacement. */ ?></div>

                    <label for="sigwm-background-rotation" class="form-label fw-bold"><?= $escape($module->framework->tt('settings_rotation_label')) /* Custom image rotation (degrees) */ ?></label>
                    <input id="sigwm-background-rotation" class="form-range" type="range" name="background_image_rotation" min="-180" max="180" step="1" value="<?= $escape($settings['background_image_rotation']) ?>">
                    <output id="sigwm-background-rotation-output" class="d-inline-block mb-1"><code><?= $escape($settings['background_image_rotation']) ?>°</code></output>
                    <div class="form-text mb-3"><?= $escape($module->framework->tt('settings_rotation_help')) /* Applies only when the custom image is selected. Positive values rotate counterclockwise. Allowed range: -180 to 180. */ ?></div>

                    <div class="small sigwm-settings-current-image">
                        <span class="fw-bold"><?= $escape($module->framework->tt('settings_current_image')) /* Current stored image */ ?>:</span>
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
                    <h2 class="fs-5 mb-2"><?= $escape($module->framework->tt('settings_preview_heading')) /* Preview */ ?></h2>
                    <div class="sigwm-settings-preview border rounded d-flex align-items-center justify-content-center p-3">
                        <img id="sigwm-custom-image-preview" src="<?= $escape($previewUrl ?? '') ?>" alt="<?= $escape($module->framework->tt('settings_preview_heading')) /* Preview */ ?>"<?= $previewUrl === null ? ' hidden' : '' ?>>
                        <p id="sigwm-custom-image-preview-empty" class="text-muted text-center mb-0"<?= $previewUrl === null ? '' : ' hidden' ?>><?= $escape($module->framework->tt('settings_preview_empty')) /* Choose a PNG to preview the custom image. */ ?></p>
                    </div>
                    <p class="form-text mb-0"><?= $escape($module->framework->tt('settings_preview_help')) /* The preview updates when you choose a replacement image or change its rotation. The final repeated watermark is additionally lightened and scaled for each signature. */ ?></p>
                </section>
            </div>
        </div>

        <button type="submit" class="btn btn-primary align-self-start"><i class="fa-solid fa-floppy-disk me-1"></i><?= $escape($module->framework->tt('settings_save')) /* Save project settings */ ?></button>
    </form>
</div>

<script src="<?= $escape($module->getUrl('js/project-settings.js')) ?>"></script>
