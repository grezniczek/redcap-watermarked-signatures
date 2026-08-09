<?php

/** @var \DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule $module */

try {
    $controller = $module->get_administrator_verification_controller();
} catch (Throwable $exception) {
    http_response_code(403);
    echo '<div class="alert alert-danger m-4">Administrator signature verification is not available for your account.</div>';
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
    'title' => 'Administrator signature verification',
    'documentation_url' => $module->getUrl('docs/administrator-guide.md'),
    'documentation_label' => 'Administrator guide',
    'documentation_help' => 'Use this Control Center page to investigate a signature across projects, review its integrity checks, and examine authorized technical history.',
    'capture_reference' => $captureReference,
    'edoc_id' => $edocId,
    'result' => $result,
    'detail_labels' => array(
        'upload_project_id' => 'Upload project ID',
        'upload_log_project_id' => 'Upload log project ID',
        'upload_log_id' => 'Upload log ID',
        'binding_project_id' => 'Binding project ID',
        'binding_log_project_id' => 'Binding log project ID',
        'binding_log_id' => 'Binding log ID',
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
