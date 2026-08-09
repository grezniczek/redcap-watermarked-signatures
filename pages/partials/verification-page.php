<?php

if (!isset($verificationPage) || !is_array($verificationPage)) {
    throw new RuntimeException('Verification page configuration is required.');
}

$escape = function ($value) {
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
};
$isAdministrator = !empty($verificationPage['is_administrator']);
$captureReference = $verificationPage['capture_reference'] ?? '';
$edocId = $verificationPage['edoc_id'] ?? '';
$result = $verificationPage['result'] ?? null;
$detailLabels = $verificationPage['detail_labels'] ?? array();
$documentationUrl = $verificationPage['documentation_url'] ?? null;
$documentationLabel = $verificationPage['documentation_label'] ?? 'Documentation';
$documentationHelp = $verificationPage['documentation_help'] ?? '';

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
    .sigwm-verification { max-width: 980px; }
    .sigwm-verification.sigwm-administrator { max-width: 1180px; }
    .sigwm-verification .sigwm-reference { max-width: 390px; }
    .sigwm-verification .sigwm-edoc { width: 150px; }
    .sigwm-verification .sigwm-reference input,
    .sigwm-verification .sigwm-reference .input-group-text { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; letter-spacing: .04em; }
    .sigwm-verification .card-body.p-3,
    .sigwm-verification .card-header.p-3 { padding-top: .6rem !important; padding-bottom: .6rem !important; }
    .sigwm-verification .alert { padding-top: .6rem; padding-bottom: .6rem; }
    .sigwm-verification .sigwm-result-table > tbody > tr > th,
    .sigwm-verification .sigwm-result-table > tbody > tr > td { padding-top: .15rem; padding-bottom: .15rem; font-weight: normal; }
    .sigwm-verification .sigwm-result-table th { width: 260px; }
    .sigwm-verification.sigwm-administrator .sigwm-result-table th { width: 280px; font-weight: normal;}
    .sigwm-verification .sigwm-diagnostic-entry + .sigwm-diagnostic-entry .sigwm-diagnostic-event-row > th,
    .sigwm-verification .sigwm-diagnostic-entry + .sigwm-diagnostic-entry .sigwm-diagnostic-event-row > td { border-top: 1px solid #444 !important; }
    .sigwm-verification .sigwm-diagnostic-json { margin: 0; border: 0; background-color: transparent; white-space: pre-wrap; font-size: .8125rem; }
    .sigwm-verification code { color: #333; overflow-wrap: anywhere; }
</style>

<div class="sigwm-verification<?= $isAdministrator ? ' sigwm-administrator' : '' ?> mb-5">
    <?php if ($isAdministrator): ?>
        <h4 style="margin-top:0;" class="clearfix"><i class="fa-solid fa-shield-halved me-2"></i><?= $escape($verificationPage['title']) ?></h4>
    <?php else: ?>
        <h1 class="projhdr"><i class="fa-solid fa-shield-halved me-2"></i><?= $escape($verificationPage['title']) ?></h1>
    <?php endif; ?>

    <?php if (is_string($documentationUrl) && $documentationUrl !== ''): ?>
        <?php if (is_string($documentationHelp) && $documentationHelp !== ''): ?>
            <p class="mb-1"><?= $escape($documentationHelp) ?></p>
        <?php endif; ?>
        <p class="mb-3">To learn more, check out the <a id="sigwm-verification-documentation" href="<?= $escape($documentationUrl) ?>" target="_blank" rel="noopener"><i class="fa-solid fa-book-open me-1"></i><?= $escape($documentationLabel) ?></a>.</p>
    <?php endif; ?>

    <form method="post" class="card card-body p-3 mb-3" autocomplete="off">
        <input type="hidden" name="redcap_csrf_token" value="<?= $escape($module->getCSRFToken()) ?>">
        <div class="d-flex flex-wrap gap-2 align-items-start">
            <div>
                <label for="sigwm-capture-ref" class="form-label fw-bold">Capture reference</label>
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
                        <?= $isAdministrator ? '' : 'required' ?>
                    >
                </div>
            </div>
            <?php if ($isAdministrator): ?>
                <div class="sigwm-edoc">
                    <label for="sigwm-edoc-id" class="form-label fw-bold">Edoc ID</label>
                    <input
                        id="sigwm-edoc-id"
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
            <?php endif; ?>
            <button type="submit" class="btn btn-sm btn-primary align-self-end">
                <i class="fa-solid fa-magnifying-glass me-1"></i> Verify
            </button>
        </div>
        <p class="text-muted mb-0">
            <?php if ($isAdministrator): ?>
                Enter either the complete value printed after <code>S:</code> in the signature watermark or an edoc ID.<br>
                Both exact lookups search provenance across all projects using this module.
            <?php else: ?>
                Enter the complete value printed after <code>S:</code> in the signature watermark.<br>
                Lookup is exact and restricted to signatures you may view in this project.
            <?php endif; ?>
        </p>
    </form>

    <?php if ($result !== null): ?>
        <div id="sigwm-verification-result"<?= $isAdministrator ? '' : ' class="fs12"' ?>>
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
                <div class="card-header fw-bold p-3 d-flex align-items-center">
                    <span><?= $isAdministrator ? 'Administrator signature details' : 'Authorized signature details' ?></span>
                    <?php if (!empty($result['field_url'])): ?>
                        <a class="ms-auto small" href="<?= $escape($result['field_url']) ?>">Go to field <i class="fa-solid fa-arrow-right"></i></a>
                    <?php endif; ?>
                </div>
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

        <?php if ($isAdministrator && !empty($result['diagnostics'])): ?>
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
        const captureReference = document.getElementById('sigwm-capture-ref');
        const edocId = document.getElementById('sigwm-edoc-id');
        if (!captureReference) return;

        const clearResultWhenInputsAreEmpty = function () {
            if (captureReference.value === '' && (!edocId || edocId.value === '')) {
                const result = document.getElementById('sigwm-verification-result');
                if (result) result.remove();
            }
        };
        captureReference.addEventListener('search', clearResultWhenInputsAreEmpty);
        if (edocId) edocId.addEventListener('search', clearResultWhenInputsAreEmpty);
    })();
</script>
