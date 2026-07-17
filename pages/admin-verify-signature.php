<?php

/** @var \DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule $module */

$escape = function ($value) {
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
};

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

$statusPresentation = array(
    'valid_current' => array('Valid and current', 'success', 'All integrity checks pass and the bound field currently contains this signature.'),
    'valid_historical' => array('Valid historical signature', 'info', 'All integrity checks pass, but the bound field no longer contains this edoc.'),
    'unbound' => array('Upload not bound', 'warning', 'Upload provenance exists, but no successful record binding exists.'),
    'invalid' => array('Verification failed', 'danger', 'One or more integrity checks failed.'),
    'incomplete' => array('Verification incomplete', 'warning', 'Required file or current-field information could not be read.'),
    'invalid_reference' => array('Invalid capture reference', 'warning', 'Enter the complete value printed after S: in the watermark.'),
    'invalid_edoc_id' => array('Invalid edoc ID', 'warning', 'Enter a positive numeric edoc ID.'),
    'invalid_lookup' => array('Choose one lookup input', 'warning', 'Enter either a capture reference or an edoc ID, not both.'),
    'unknown' => array('Not found', 'secondary', 'No signature provenance is available for this lookup.'),
    'access_denied' => array('Not available', 'secondary', 'No signature is available for this reference.')
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
    'upload_project_id' => 'Upload project ID',
    'upload_log_project_id' => 'Upload log project ID',
    'upload_log_id' => 'Upload log ID',
    'binding_project_id' => 'Binding project ID',
    'binding_log_project_id' => 'Binding log project ID',
    'binding_log_id' => 'Binding log ID',
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

$diagnosticSummaryLabels = array(
    'log_id' => 'Log ID',
    'timestamp' => 'Timestamp',
    'username' => 'Actor',
    'project_id' => 'Project',
    'record' => 'Record',
    'edoc_id' => 'Edoc ID'
);
?>

<style>
    .sigwm-admin-verify { max-width: 1180px; }
    .sigwm-admin-verify .sigwm-reference { max-width: 390px; }
    .sigwm-admin-verify .sigwm-edoc { width: 150px; }
    .sigwm-admin-verify .sigwm-reference input,
    .sigwm-admin-verify .sigwm-reference .input-group-text { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; letter-spacing: .04em; }
    .sigwm-admin-verify .card-body.p-3,
    .sigwm-admin-verify .card-header.p-3 { padding-top: .6rem !important; padding-bottom: .6rem !important; }
    .sigwm-admin-verify .alert { padding-top: .6rem; padding-bottom: .6rem; }
    .sigwm-admin-verify .sigwm-result-table > tbody > tr > th,
    .sigwm-admin-verify .sigwm-result-table > tbody > tr > td { padding-top: .15rem; padding-bottom: .15rem; }
    .sigwm-admin-verify .sigwm-result-table th { width: 280px; }
    .sigwm-admin-verify .sigwm-diagnostic-entry + .sigwm-diagnostic-entry .sigwm-diagnostic-event-row > th,
    .sigwm-admin-verify .sigwm-diagnostic-entry + .sigwm-diagnostic-entry .sigwm-diagnostic-event-row > td { border-top: 1px solid #444 !important; }
    .sigwm-admin-verify .sigwm-diagnostic-json { margin: 0; border: 0; background-color: transparent; white-space: pre-wrap; }
    .sigwm-admin-verify code { color: #333; overflow-wrap: anywhere; }
    .sigwm-admin-verify .sigwm-diagnostic-json { font-size: .8125rem; }
</style>

<div class="sigwm-admin-verify mt-3 mb-5">
    <h3><i class="fa-solid fa-shield-halved me-2"></i>Administrator signature verification</h3>

    <form method="post" class="card card-body p-3 mb-3" autocomplete="off">
        <input type="hidden" name="redcap_csrf_token" value="<?= $escape($module->getCSRFToken()) ?>">
        <div class="d-flex flex-wrap gap-2 align-items-start">
            <div>
                <label for="sigwm-admin-capture-ref" class="form-label fw-bold">Capture reference</label>
                <div class="input-group input-group-sm sigwm-reference">
                    <span class="input-group-text">S:</span>
                    <input
                        id="sigwm-admin-capture-ref"
                        class="form-control"
                        type="search"
                        name="capture_ref"
                        value="<?= $escape($captureReference) ?>"
                        maxlength="32"
                        placeholder="5622-9F1F-AHCA-K"
                        spellcheck="false"
                    >
                </div>
            </div>
            <div class="sigwm-edoc">
                <label for="sigwm-admin-edoc-id" class="form-label fw-bold">Edoc ID</label>
                <input
                    id="sigwm-admin-edoc-id"
                    class="form-control form-control-sm"
                    type="search"
                    name="edoc_id"
                    value="<?= $escape($edocId) ?>"
                    inputmode="numeric"
                    maxlength="20"
                    placeholder="1903"
                    spellcheck="false"
                >
            </div>
            <button type="submit" class="btn btn-sm btn-primary align-self-end">
                <i class="fa-solid fa-magnifying-glass me-1"></i> Verify
            </button>
        </div>
        <p class="text-muted mb-0">
            Enter either the complete value printed after <code>S:</code> in the signature watermark or an edoc ID.<br>
            Both exact lookups search provenance across all projects using this module.
        </p>
    </form>

    <?php if ($result !== null): ?>
        <div id="sigwm-admin-verification-result">
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
                <div class="card-header fw-bold p-3">Administrator signature details</div>
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

        <?php if (!empty($result['diagnostics'])): ?>
            <div class="card mb-4">
                <div class="card-header fw-bold p-3">Technical log history</div>
                <div class="card-body p-0">
                    <?php foreach ($result['diagnostics'] as $diagnostic): ?>
                        <?php
                        $diagnosticDetails = $diagnostic;
                        unset($diagnosticDetails['log_id'], $diagnosticDetails['timestamp'], $diagnosticDetails['username']);
                        unset($diagnosticDetails['message'], $diagnosticDetails['project_id'], $diagnosticDetails['record'], $diagnosticDetails['edoc_id']);
                        $diagnosticJson = json_encode($diagnosticDetails, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                        if (!is_string($diagnosticJson)) $diagnosticJson = '{}';
                        ?>
                        <div class="sigwm-diagnostic-entry">
                            <table class="table table-sm table-striped mb-0 sigwm-result-table">
                                <tbody>
                                    <tr class="sigwm-diagnostic-event-row">
                                        <th class="ps-3">Log event</th>
                                        <td><code><?= $escape($diagnostic['message'] ?? 'unknown event') ?></code></td>
                                    </tr>
                                <?php foreach ($diagnosticSummaryLabels as $key => $label): ?>
                                    <tr>
                                        <th class="ps-3"><?= $escape($label) ?></th>
                                        <td><code><?= array_key_exists($key, $diagnostic) ? $escape($diagnostic[$key]) : '&mdash;' ?></code></td>
                                    </tr>
                                <?php endforeach; ?>
                                    <tr>
                                        <th class="ps-3">Details</th>
                                        <td><pre class="sigwm-diagnostic-json"><code><?= $escape($diagnosticJson) ?></code></pre></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    <?php endforeach; ?>
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
        const captureReference = document.getElementById('sigwm-admin-capture-ref');
        const edocId = document.getElementById('sigwm-admin-edoc-id');
        if (!captureReference || !edocId) return;

        const clearResultWhenInputsAreEmpty = function () {
            if (captureReference.value === '' && edocId.value === '') {
                const result = document.getElementById('sigwm-admin-verification-result');
                if (result) result.remove();
            }
        };
        captureReference.addEventListener('search', clearResultWhenInputsAreEmpty);
        edocId.addEventListener('search', clearResultWhenInputsAreEmpty);
    })();
</script>
