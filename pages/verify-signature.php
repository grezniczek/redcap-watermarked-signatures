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
        'capture_ref' => 'Capture reference',
        'context_ref' => 'Context reference',
        'project_reference' => 'Public project reference',
        'anchor' => 'Visible anchor',
        'record_id' => 'Record ID',
        'event_id' => 'Event ID',
        'instrument' => 'Instrument',
        'field' => 'Field',
        'repeat_type' => 'Repeat type',
        'repeat_instrument' => 'Repeat instrument',
        'repeat_instance' => 'Repeat instance',
        'edoc_id' => 'Edoc ID',
        'capture_origin' => 'Capture origin',
        'capture_username' => 'Capture username',
        'captured_at' => 'Captured at (UTC)',
        'save_origin' => 'Save origin',
        'save_username' => 'Save username',
        'bound_at' => 'Bound at (UTC)',
        'watermark_version' => 'Watermark version',
        'file_sha256' => 'Stored SHA-256'
    )
);

require __DIR__ . '/partials/verification-page.php';
