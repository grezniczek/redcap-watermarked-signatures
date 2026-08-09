<?php

/** @var \DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule $module */

try {
    if (!defined('PROJECT_ID') || !is_numeric(PROJECT_ID)) {
        throw new RuntimeException('Project context is required.');
    }
    $controller = $module->get_project_verification_controller((int) PROJECT_ID);
} catch (Throwable $exception) {
    http_response_code(403);
    $unavailableMessage = $module->framework->tt('ui_project_verification_unavailable'); // Signature verification is not available for your account in this project.
    echo '<div class="alert alert-danger m-4">' . htmlspecialchars($unavailableMessage, ENT_QUOTES, 'UTF-8') . '</div>';
    return;
}

$captureReference = '';
$result = null;
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $submittedReference = isset($_POST['capture_ref']) ? strtoupper(trim((string) $_POST['capture_ref'])) : '';
    $result = $controller->verify($submittedReference);
    $normalizedReference = \DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator::normalizeCaptureReference($submittedReference);
    $captureReference = $normalizedReference === null ? $submittedReference : substr($normalizedReference, 2);
}

$verificationPage = array(
    'is_administrator' => false,
    'title' => $module->framework->tt('ui_project_verification_title'), // Verify watermarked signature
    'documentation_url' => $module->getUrl('docs/project-user-guide.md'),
    'documentation_label' => $module->framework->tt('ui_project_user_guide'), // Project user guide
    'documentation_help' => $module->framework->tt('ui_project_verification_guide_help'), // Use this page to confirm whether a watermarked signature is valid, still current in its field, or requires follow-up.
    'capture_reference' => $captureReference,
    'result' => $result,
    'detail_labels' => array(
        'capture_ref' => $module->framework->tt('ui_label_capture_reference'), // Capture reference
        'context_ref' => $module->framework->tt('ui_label_context_reference'), // Context reference
        'project_reference' => $module->framework->tt('ui_label_public_project_reference'), // Public project reference
        'anchor' => $module->framework->tt('ui_label_visible_anchor'), // Visible anchor
        'record_id' => $module->framework->tt('ui_label_record_id'), // Record ID
        'event_id' => $module->framework->tt('ui_label_event_id'), // Event ID
        'instrument' => $module->framework->tt('ui_label_instrument'), // Instrument
        'field' => $module->framework->tt('ui_label_field'), // Field
        'repeat_type' => $module->framework->tt('ui_label_repeat_type'), // Repeat type
        'repeat_instrument' => $module->framework->tt('ui_label_repeat_instrument'), // Repeat instrument
        'repeat_instance' => $module->framework->tt('ui_label_repeat_instance'), // Repeat instance
        'edoc_id' => $module->framework->tt('ui_label_edoc_id'), // Edoc ID
        'capture_origin' => $module->framework->tt('ui_label_capture_origin'), // Capture origin
        'capture_username' => $module->framework->tt('ui_label_capture_username'), // Capture username
        'captured_at' => $module->framework->tt('ui_label_captured_at'), // Captured at (UTC)
        'save_origin' => $module->framework->tt('ui_label_save_origin'), // Save origin
        'save_username' => $module->framework->tt('ui_label_save_username'), // Save username
        'bound_at' => $module->framework->tt('ui_label_bound_at'), // Bound at (UTC)
        'watermark_version' => $module->framework->tt('ui_label_watermark_version'), // Watermark version
        'file_sha256' => $module->framework->tt('ui_label_stored_sha256'), // Stored SHA-256
        'background_image_mode' => $module->framework->tt('ui_label_background_image_mode'), // Selected background image
        'background_image_effective_mode' => $module->framework->tt('ui_label_background_image_effective_mode'), // Applied background image
        'background_image_sha256' => $module->framework->tt('ui_label_background_image_sha256') // Custom background image SHA-256
    )
);

require __DIR__ . '/partials/verification-page.php';
