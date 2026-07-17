<?php

/** @var \DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule $module */

$escape = function ($value) {
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
};

try {
    if (!defined('PROJECT_ID') || !is_numeric(PROJECT_ID)) {
        throw new RuntimeException('Project context is required.');
    }
    $controller = $module->get_project_verification_controller((int) PROJECT_ID);
} catch (Throwable $exception) {
    http_response_code(403);
    echo '<div class="alert alert-danger m-4">Signature verification is not available for your account in this project.</div>';
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

$statusPresentation = array(
    'valid_current' => array('Valid and current', 'success', 'All integrity checks pass and the bound field currently contains this signature.'),
    'valid_historical' => array('Valid historical signature', 'info', 'All integrity checks pass, but the bound field no longer contains this edoc.'),
    'unbound' => array('Upload not bound', 'warning', 'Upload provenance exists, but no successful record binding exists.'),
    'invalid' => array('Verification failed', 'danger', 'One or more integrity checks failed.'),
    'incomplete' => array('Verification incomplete', 'warning', 'Required file or current-field information could not be read.'),
    'invalid_reference' => array('Invalid capture reference', 'warning', 'Enter the complete value printed after S: in the watermark.'),
    'unknown' => array('Not available', 'secondary', 'No signature is available for this reference in your authorized project scope.'),
    'access_denied' => array('Not available', 'secondary', 'No signature is available for this reference in your authorized project scope.')
);

$checkLabels = array(
    'binding_mac' => 'Binding MAC',
    'binding_upload' => 'Upload/binding relationship',
    'anchor' => 'Stable-scope anchor',
    'edoc_exists' => 'Edoc exists',
    'file_digest' => 'Final edoc SHA-256',
    'current_field' => 'Field currently points to edoc'
);

$detailLabels = array(
    'capture_ref' => 'Capture reference',
    'context_ref' => 'Context reference',
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
);
?>

<style>
    .sigwm-verify { max-width: 980px; }
    .sigwm-verify .sigwm-reference { max-width: 390px; }
    .sigwm-verify .sigwm-reference input,
    .sigwm-verify .sigwm-reference .input-group-text { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; letter-spacing: .04em; }
    .sigwm-verify .card-body.p-3,
    .sigwm-verify .card-header.p-3 { padding-top: .6rem !important; padding-bottom: .6rem !important; }
    .sigwm-verify .alert { padding-top: .6rem; padding-bottom: .6rem; }
    .sigwm-verify .sigwm-result-table > tbody > tr > th,
    .sigwm-verify .sigwm-result-table > tbody > tr > td { padding-top: .15rem; padding-bottom: .15rem; }
    .sigwm-verify .sigwm-result-table th { width: 260px; }
    .sigwm-verify code { color: #333; overflow-wrap: anywhere; }
</style>

<div class="sigwm-verify mt-3 mb-5">
    <h3><i class="fa-solid fa-shield-halved me-2"></i>Verify watermarked signature</h3>

    <form method="post" class="card card-body p-3 mb-3" autocomplete="off">
        <input type="hidden" name="redcap_csrf_token" value="<?= $escape($module->getCSRFToken()) ?>">
        <label for="sigwm-capture-ref" class="form-label fw-bold">Capture reference</label>
        <div class="d-flex flex-wrap gap-2 align-items-start">
            <div class="input-group input-group-sm sigwm-reference">
                <span class="input-group-text">S:</span>
                <input
                    id="sigwm-capture-ref"
                    class="form-control"
                    type="search"
                    name="capture_ref"
                    value="<?= $escape($captureReference) ?>"
                    maxlength="32"
                    placeholder="5622-9F1F-AHCA-K"
                    spellcheck="false"
                    required
                >
            </div>
            <button type="submit" class="btn btn-sm btn-primary">
                <i class="fa-solid fa-magnifying-glass me-1"></i> Verify
            </button>
        </div>
        <p class="text-muted mb-0">
            Enter the complete value printed after <code>S:</code> in the signature watermark.<br>
            Lookup is exact and restricted to signatures you may view in this project.
        </p>
    </form>

    <?php if ($result !== null): ?>
        <div id="sigwm-verification-result" class="fs12">
        <?php
        $status = $result['status'] ?? 'incomplete';
        $presentation = $statusPresentation[$status] ?? $statusPresentation['incomplete'];
        ?>
        <div class="alert alert-<?= $escape($presentation[1]) ?>">
            <div class="fw-bold fs-5"><?= $escape($presentation[0]) ?></div>
            <div><?= $escape($presentation[2]) ?></div>
        </div>

        <?php if (!empty($result['checks'])): ?>
            <div class="card mb-4">
                <div class="card-header fw-bold p-3">Verification checks</div>
                <div class="card-body p-0">
                    <table class="table table-sm table-striped mb-0 sigwm-result-table">
                        <tbody>
                        <?php foreach ($checkLabels as $key => $label): ?>
                            <?php if (!array_key_exists($key, $result['checks'])) continue; ?>
                            <?php
                            $value = $result['checks'][$key];
                            $badge = $value === true
                                ? '<span class="badge bg-success">Pass</span>'
                                : ($value === false
                                    ? '<span class="badge bg-danger">Fail</span>'
                                    : '<span class="badge bg-secondary">Not checked</span>');
                            ?>
                            <tr>
                                <th class="ps-3"><?= $escape($label) ?></th>
                                <td><?= $badge ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>

        <?php if (!empty($result['details'])): ?>
            <div class="card mb-4">
                <div class="card-header fw-bold p-3">Authorized signature details</div>
                <div class="card-body p-0">
                    <table class="table table-sm table-striped mb-0 sigwm-result-table">
                        <tbody>
                        <?php foreach ($detailLabels as $key => $label): ?>
                            <?php if (!array_key_exists($key, $result['details'])) continue; ?>
                            <?php $value = $result['details'][$key]; ?>
                            <tr>
                                <th class="ps-3"><?= $escape($label) ?></th>
                                <td><code><?= $value === null || $value === '' ? '&mdash;' : $escape($value) ?></code></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>

        <?php if (!empty($result['issues']) && !in_array($status, array('unknown', 'access_denied'), true)): ?>
            <div class="small text-muted">
                Technical findings:
                <code><?= $escape(implode(', ', $result['issues'])) ?></code>
            </div>
        <?php endif; ?>
        </div>
    <?php endif; ?>
</div>

<script>
    (function () {
        const captureReference = document.getElementById('sigwm-capture-ref');
        if (!captureReference) return;

        captureReference.addEventListener('search', function () {
            if (captureReference.value === '') {
                const result = document.getElementById('sigwm-verification-result');
                if (result) result.remove();
            }
        });
    })();
</script>
