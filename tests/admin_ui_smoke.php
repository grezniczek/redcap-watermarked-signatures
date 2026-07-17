<?php

require_once __DIR__ . '/../classes/Crypto/Base32.php';
require_once __DIR__ . '/../classes/Crypto/Base64Url.php';
require_once __DIR__ . '/../classes/Crypto/ReferenceGenerator.php';
require_once __DIR__ . '/../classes/Verification/AdministratorVerificationController.php';

use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\AdministratorVerificationController;

function adminUiAssert($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

class AdministratorUiRepository
{
    public $diagnostics = array();
    public $upload = null;
    public $requestedEdocId = null;

    public function findDiagnosticEventsByEdocId($edocId)
    {
        $this->requestedEdocId = (int) $edocId;
        return $this->diagnostics;
    }

    public function findUploadByEdocId($edocId)
    {
        return (int) $edocId === 1903 ? $this->upload : null;
    }
}

class AdministratorUiService
{
    public $result;
    public $calls = 0;
    public $lastReference = null;
    public $lastProjectId = 'unset';

    public function verify($captureReference, $projectId = null)
    {
        $this->calls++;
        $this->lastReference = $captureReference;
        $this->lastProjectId = $projectId;
        return $this->result;
    }
}

$captureReference = ReferenceGenerator::captureReference();
$repository = new AdministratorUiRepository();
$repository->diagnostics = array(array(
    'log_id' => 88,
    'timestamp' => '2026-07-17 13:02:15',
    'username' => 'admin',
    'project_id' => 461,
    'record' => '9',
    'message' => 'sigwm_bind',
    'edoc_id' => 1903,
    'capture_ref' => $captureReference,
    'technical_message' => 'Binding review note.',
    'payload_json' => '{"envelope_nonce":"must-not-be-presented"}',
    'binding_mac' => 'must-not-be-presented'
));
$service = new AdministratorUiService();
$service->result = array(
    'status' => 'valid_current',
    'binding_state' => 'bound',
    'integrity' => 'valid',
    'current_state' => 'current',
    'capture_ref' => $captureReference,
    'checks' => array('binding_mac' => true, 'current_field' => true),
    'issues' => array(),
    'edoc' => array('exists' => true, 'readable' => true),
    'upload' => array(
        'pid' => 461,
        '_project_id' => 461,
        '_log_id' => 87,
        'capture_ref' => $captureReference,
        'context_ref' => 'C-1111-2222-3333-4',
        'anchor' => 'AAAA-BBBB-CCCC-DDDD',
        'capture_origin' => 'data_entry',
        'capture_username' => 'capture-user',
        'captured_at' => '2026-07-17T13:00:00Z',
        'edoc_id' => 1903,
        'file_sha256' => str_repeat('a', 64),
        'watermark_version' => 1,
        'envelope_nonce' => 'must-not-be-presented'
    ),
    'binding' => array(
        'pid' => 461,
        '_project_id' => 461,
        '_log_id' => 88,
        'record_id' => '9',
        'event_id' => 1423,
        'instrument' => 'form_1',
        'field' => 'esig',
        'repeat_type' => null,
        'repeat_instrument' => null,
        'repeat_instance' => null,
        'bound_at' => '2026-07-17T13:02:15Z',
        'save_origin' => 'data_entry',
        'save_username' => 'save-user',
        'watermark_version' => 1,
        'binding_mac' => 'must-not-be-presented'
    )
);
$repository->upload = $service->result['upload'];

$controller = new AdministratorVerificationController($repository, $service);
$presented = $controller->verify(substr($captureReference, 2));
adminUiAssert($service->calls === 1, 'Administrator verification did not invoke the service.');
adminUiAssert($service->lastReference === $captureReference && $service->lastProjectId === null, 'Administrator lookup was not normalized or global.');
adminUiAssert($repository->requestedEdocId === 1903, 'Administrator diagnostics did not use the verified upload edoc.');
adminUiAssert($presented['details']['upload_project_id'] === 461, 'Upload project ID was not presented.');
adminUiAssert($presented['details']['binding_log_id'] === 88, 'Binding log ID was not presented.');
adminUiAssert(!isset($presented['details']['envelope_nonce']) && !isset($presented['details']['binding_mac']), 'Sensitive verification values escaped administrator details.');
adminUiAssert(count($presented['diagnostics']) === 1, 'Administrator diagnostic history was not presented.');
adminUiAssert(!isset($presented['diagnostics'][0]['payload_json']) && !isset($presented['diagnostics'][0]['binding_mac']), 'Raw diagnostic payload values escaped administrator history.');
$byEdocId = $controller->verifyEdocId('1903');
adminUiAssert($byEdocId['lookup_type'] === 'edoc_id' && $byEdocId['lookup_value'] === 1903, 'Administrator edoc lookup was not identified as an edoc lookup.');
adminUiAssert($service->lastReference === $captureReference && $service->lastProjectId === null, 'Administrator edoc lookup was not verified globally.');
adminUiAssert($controller->verifyEdocId('not-an-edoc')['status'] === 'invalid_edoc_id', 'Invalid administrator edoc ID was not rejected.');
$repository->upload = null;
adminUiAssert($controller->verifyEdocId('9999')['status'] === 'unknown', 'Unknown administrator edoc ID was not reported as unknown.');

$config = json_decode(file_get_contents(__DIR__ . '/../config.json'), true);
adminUiAssert(is_array($config), 'config.json is invalid JSON.');
$controlCenterLinks = $config['links']['control-center'] ?? array();
adminUiAssert(count($controlCenterLinks) === 1, 'Administrator verification control-center link is not configured.');
adminUiAssert($controlCenterLinks[0]['key'] === 'administrator-signature-verification', 'Administrator verification link key is incorrect.');
adminUiAssert($controlCenterLinks[0]['url'] === 'pages/admin-verify-signature.php', 'Administrator verification link target is incorrect.');
adminUiAssert($controlCenterLinks[0]['show-header-and-footer'] === true, 'Administrator verification page does not request the REDCap layout.');

$pageSource = file_get_contents(__DIR__ . '/../pages/admin-verify-signature.php');
adminUiAssert(strpos($pageSource, 'method="post"') !== false, 'Administrator verification form does not use POST.');
adminUiAssert(strpos($pageSource, 'redcap_csrf_token') !== false, 'Administrator verification form is missing the REDCap CSRF token.');
adminUiAssert(strpos($pageSource, 'type="search"') !== false, 'Administrator verification input is not a search control.');
adminUiAssert(strpos($pageSource, 'name="edoc_id"') !== false, 'Administrator edoc lookup input is missing.');
adminUiAssert(strpos($pageSource, 'verifyEdocId') !== false, 'Administrator page does not invoke edoc verification.');
adminUiAssert(strpos($pageSource, 'id="sigwm-admin-verification-result"') !== false, 'Administrator verification result wrapper is missing.');
adminUiAssert(strpos($pageSource, "captureReference.addEventListener('search'") !== false, 'Administrator search clear handler is missing.');
adminUiAssert(strpos($pageSource, "edocId.addEventListener('search'") !== false, 'Administrator edoc search clear handler is missing.');
adminUiAssert(strpos($pageSource, "result.remove()") !== false, 'Administrator search clear handler does not clear the result.');
adminUiAssert(strpos($pageSource, 'Technical log history') !== false, 'Administrator technical history is not rendered.');
adminUiAssert(strpos($pageSource, 'JSON_PRETTY_PRINT') !== false, 'Administrator diagnostic details are not pretty-printed.');
adminUiAssert(strpos($pageSource, '>Log event</th>') !== false, 'Administrator diagnostic event row is missing.');
adminUiAssert(strpos($pageSource, 'border-top: 2px solid #444') !== false, 'Administrator diagnostic entries are not visibly separated.');

echo "Watermarked Signatures administrator UI smoke tests passed.\n";
