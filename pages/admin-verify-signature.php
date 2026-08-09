<?php

/** @var \DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule $module */

try {
    $controller = $module->get_administrator_verification_controller();
} catch (Throwable $exception) {
    http_response_code(403);
    $unavailableMessage = $module->framework->tt('ui_administrator_verification_unavailable'); // Administrator signature verification is not available for your account.
    echo '<div class="alert alert-danger m-4">' . htmlspecialchars($unavailableMessage, ENT_QUOTES, 'UTF-8') . '</div>';
    return;
}

$captureReference = '';
$edocId = '';
$result = null;
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $submittedReference = isset($_POST['capture_ref']) ? strtoupper(trim((string) $_POST['capture_ref'])) : '';
    $submittedEdocId = isset($_POST['edoc_id']) ? trim((string) $_POST['edoc_id']) : '';
    if ($submittedReference !== '' && $submittedEdocId !== '') {
        $result = array(
            'status' => 'invalid_lookup',
            'binding_state' => 'unknown',
            'integrity' => 'not_checked',
            'current_state' => 'unknown',
            'checks' => array(),
            'issues' => array('ambiguous_lookup'),
            'edoc' => null,
            'details' => array(),
            'diagnostics' => array()
        );
        $captureReference = $submittedReference;
        $edocId = $submittedEdocId;
    } elseif ($submittedEdocId !== '') {
        $result = $controller->verifyEdocId($submittedEdocId);
        $edocId = $submittedEdocId;
    } else {
        $result = $controller->verify($submittedReference);
        $normalizedReference = \DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator::normalizeCaptureReference($submittedReference);
        $captureReference = $normalizedReference === null ? $submittedReference : substr($normalizedReference, 2);
    }
}

$verificationPage = array(
    'is_administrator' => true,
    'title' => $module->framework->tt('ui_administrator_verification_title'), // Administrator signature verification
    'documentation_url' => $module->getUrl('docs/administrator-guide.md'),
    'documentation_label' => $module->framework->tt('ui_administrator_guide'), // Administrator guide
    'documentation_help' => $module->framework->tt('ui_administrator_verification_guide_help'), // Use this Control Center page to investigate a signature across projects, review its integrity checks, and examine authorized technical history.
    'capture_reference' => $captureReference,
    'edoc_id' => $edocId,
    'result' => $result,
    'detail_labels' => array(
        'upload_project_id' => $module->framework->tt('ui_label_upload_project_id'), // Upload project ID
        'upload_log_project_id' => $module->framework->tt('ui_label_upload_log_project_id'), // Upload log project ID
        'upload_log_id' => $module->framework->tt('ui_label_upload_log_id'), // Upload log ID
        'binding_project_id' => $module->framework->tt('ui_label_binding_project_id'), // Binding project ID
        'binding_log_project_id' => $module->framework->tt('ui_label_binding_log_project_id'), // Binding log project ID
        'binding_log_id' => $module->framework->tt('ui_label_binding_log_id'), // Binding log ID
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
        'background_image_sha256' => $module->framework->tt('ui_label_background_image_sha256'), // Custom background image SHA-256
        'background_image_rotation' => $module->framework->tt('ui_label_background_image_rotation') // Applied background image rotation
    )
);

require __DIR__ . '/partials/verification-page.php';
