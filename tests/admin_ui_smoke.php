<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Tests;

require_once __DIR__ . '/../classes/Crypto/Base32.php';
require_once __DIR__ . '/../classes/Crypto/Base64Url.php';
require_once __DIR__ . '/../classes/Crypto/ReferenceGenerator.php';
require_once __DIR__ . '/../classes/Verification/RedcapFieldLink.php';
require_once __DIR__ . '/../classes/Verification/DatabaseQueryToolAccess.php';
require_once __DIR__ . '/../classes/Verification/AdministratorVerificationController.php';

use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\AdministratorVerificationController;
use RuntimeException;

if (!defined('APP_PATH_WEBROOT')) {
    define('APP_PATH_WEBROOT', '/redcap/');
}
if (!defined('SUPER_USER')) {
    define('SUPER_USER', true);
}
$GLOBALS['database_query_tool_enabled'] = '1';

function adminUiAssert($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

class AdministratorUiRepository
{
    public $diagnostics = array();
    public $renameDiagnostics = array();
    public $upload = null;
    public $requestedEdocId = null;
    public $requestedRenameProjectId = null;
    public $requestedRenameRecordId = null;

    public function findDiagnosticEventsByEdocId($edocId)
    {
        $this->requestedEdocId = (int) $edocId;
        return $this->diagnostics;
    }

    public function findUploadByEdocId($edocId)
    {
        return (int) $edocId === 1903 ? $this->upload : null;
    }

    public function findRecordRenameEventsByCurrentRecord($projectId, $recordId)
    {
        $this->requestedRenameProjectId = (int) $projectId;
        $this->requestedRenameRecordId = (string) $recordId;
        return $this->renameDiagnostics;
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

class AdministratorUiEconsentIpService
{
    public $revealArguments = array();
    public $dataEntryRevealArguments = array();

    public function compare($binding, $recordId, $revealIps)
    {
        $this->revealArguments[] = $revealIps;
        return array(
            'status' => 'mismatch',
            'warning' => true,
            'signature_upload_ip' => '203.0.113.25',
            'econsent_submission_ip' => '203.0.113.26'
        );
    }

    public function dataEntrySignatureIp($binding, $revealIps)
    {
        $this->dataEntryRevealArguments[] = $revealIps;
        return $revealIps
            ? array('status' => 'captured', 'signature_upload_ip' => '203.0.113.27')
            : array('status' => 'captured');
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
$repository->renameDiagnostics = array(array(
    'log_id' => 89,
    'timestamp' => '2026-07-17 20:00:07',
    'username' => 'gr',
    'project_id' => 461,
    'record' => '12',
    'message' => 'sigwm_record_rename',
    'previous_record_id' => '9',
    'rename_origin' => 'data_entry_record_home',
    'rename_username' => 'gr',
    'renamed_at' => '2026-07-17T20:00:07.906Z'
));
$service = new AdministratorUiService();
$service->result = array(
    'status' => 'valid_current',
    'binding_state' => 'bound',
    'integrity' => 'valid',
    'current_state' => 'current',
    'capture_ref' => $captureReference,
    'current_record_id' => '12',
    'checks' => array('binding_mac' => true, 'current_field' => true),
    'issues' => array(),
    'edoc' => array('exists' => true, 'readable' => true),
    'upload' => array(
        'pid' => 461,
        '_project_id' => 461,
        '_log_id' => 87,
        'capture_ref' => $captureReference,
        'context_ref' => 'C:1111-2222-3333-4',
        'anchor' => 'A:AAAA-BBBB-CCCC-DDDD',
        'capture_origin' => 'data_entry',
        'capture_username' => 'capture-user',
        'captured_at' => '2026-07-17T13:00:00Z',
        'edoc_id' => 1903,
        'file_sha256' => str_repeat('a', 64),
        'project_reference' => 'SIGWM-TEST',
        'field_reference' => 'CONSENT',
        'background_image_mode' => 'custom',
        'background_image_effective_mode' => 'custom',
        'background_image_sha256' => str_repeat('b', 64),
        'background_image_rotation' => -30,
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
adminUiAssert($presented['details']['record_id'] === '12', 'Administrator details did not present the current record ID.');
adminUiAssert($presented['details']['project_reference'] === 'SIGWM-TEST', 'Administrator details did not present the public project reference.');
adminUiAssert($presented['details']['field_reference'] === 'CONSENT', 'Administrator details did not present the field reference.');
adminUiAssert($presented['details']['background_image_mode'] === 'custom', 'Administrator details did not present the selected background image mode.');
adminUiAssert($presented['details']['background_image_effective_mode'] === 'custom', 'Administrator details did not present the applied background image mode.');
adminUiAssert($presented['details']['background_image_sha256'] === str_repeat('b', 64), 'Administrator details did not present the custom background image digest.');
adminUiAssert($presented['details']['background_image_rotation'] === -30, 'Administrator details did not present the applied background image rotation.');
adminUiAssert($presented['details']['capture_ref'] === $captureReference, 'Administrator details did not retain the canonical S: capture-reference format.');
adminUiAssert($presented['details']['context_ref'] === 'C:1111-2222-3333-4', 'Administrator details did not use the C: context-reference display format.');
adminUiAssert($presented['details']['anchor'] === 'A:AAAA-BBBB-CCCC-DDDD', 'Administrator details did not use the A: anchor display format.');
adminUiAssert($presented['field_url'] === '/redcap/DataEntry/index.php?pid=461&id=12&event_id=1423&page=form_1&instance=1', 'Administrator verification did not create the data-entry field URL.');
adminUiAssert(!isset($presented['details']['envelope_nonce']) && !isset($presented['details']['binding_mac']), 'Sensitive verification values escaped administrator details.');
adminUiAssert($repository->requestedRenameProjectId === 461 && $repository->requestedRenameRecordId === '12', 'Administrator history did not use the current binding record.');
adminUiAssert(count($presented['diagnostics']) === 2, 'Administrator diagnostic history was not presented.');
adminUiAssert($presented['diagnostics'][0]['message'] === 'sigwm_record_rename', 'Administrator history was not sorted with the newest event first.');
adminUiAssert(!isset($presented['diagnostics'][1]['payload_json']) && !isset($presented['diagnostics'][1]['binding_mac']), 'Raw diagnostic payload values escaped administrator history.');
adminUiAssert($presented['diagnostics'][0]['record'] === '12' && $presented['diagnostics'][0]['previous_record_id'] === '9', 'Administrator history did not preserve record-rename details.');
$service->result['checks']['binding_econsent_ip_mac'] = true;
$service->result['binding']['v'] = 3;
$service->result['binding']['econsent_survey_id'] = 715;
$service->result['binding']['econsent_ip_system_setting_enabled'] = true;
$service->result['binding']['econsent_ip_capture_status'] = 'captured';
$noRevealIpService = new AdministratorUiEconsentIpService();
$noRevealController = new AdministratorVerificationController($repository, $service, $noRevealIpService, false);
$noReveal = $noRevealController->verify(substr($captureReference, 2));
adminUiAssert($noRevealIpService->revealArguments === array(false), 'Administrator without Database Query Tool access requested plaintext IP values.');
adminUiAssert(
    ($noReveal['econsent_ip_diagnostic']['status'] ?? null) === 'mismatch'
        && !isset($noReveal['econsent_ip_diagnostic']['signature_upload_ip'])
        && !isset($noReveal['econsent_ip_diagnostic']['econsent_submission_ip'])
        && ($noReveal['details']['econsent_ip_system_setting_enabled'] ?? null) === true
        && ($noReveal['details']['signature_upload_ip'] ?? null) === AdministratorVerificationController::DETAIL_CAPTURED_ENCRYPTED
        && ($noReveal['details']['econsent_submission_ip'] ?? null) === AdministratorVerificationController::DETAIL_CAPTURED_ENCRYPTED
        && $noReveal['can_reveal_econsent_ips'] === false,
    'Administrator diagnostics exposed IP addresses without Database Query Tool access.'
);
$GLOBALS['database_query_tool_enabled'] = '0';
$disabledDqtIpService = new AdministratorUiEconsentIpService();
$disabledDqtController = new AdministratorVerificationController($repository, $service, $disabledDqtIpService, true);
$disabledDqt = $disabledDqtController->verify(substr($captureReference, 2));
adminUiAssert(
    $disabledDqtIpService->revealArguments === array(false)
        && ($disabledDqt['details']['signature_upload_ip'] ?? null) === AdministratorVerificationController::DETAIL_CAPTURED_ENCRYPTED
        && ($disabledDqt['details']['econsent_submission_ip'] ?? null) === AdministratorVerificationController::DETAIL_CAPTURED_ENCRYPTED
        && $disabledDqt['can_reveal_econsent_ips'] === false,
    'Administrator diagnostics exposed IP addresses while the Database Query Tool was disabled.'
);
$GLOBALS['database_query_tool_enabled'] = '1';
$revealIpService = new AdministratorUiEconsentIpService();
$revealController = new AdministratorVerificationController($repository, $service, $revealIpService, true);
$revealed = $revealController->verify(substr($captureReference, 2));
adminUiAssert(
    $revealIpService->revealArguments === array(true)
        && ($revealed['econsent_ip_diagnostic']['signature_upload_ip'] ?? null) === '203.0.113.25'
        && ($revealed['econsent_ip_diagnostic']['econsent_submission_ip'] ?? null) === '203.0.113.26'
        && ($revealed['details']['signature_upload_ip'] ?? null) === '203.0.113.25'
        && ($revealed['details']['econsent_submission_ip'] ?? null) === '203.0.113.26'
        && $revealed['can_reveal_econsent_ips'] === true,
    'Administrator details did not reveal IP addresses after Database Query Tool access was confirmed.'
);
$service->result['binding']['capture_origin'] = 'data_entry';
$service->result['binding']['econsent_survey_id'] = null;
$service->result['binding']['econsent_ip_system_setting_enabled'] = null;
$service->result['binding']['econsent_ip_capture_status'] = 'not_applicable';
$service->result['binding']['econsent_signature_ip_ciphertext'] = null;
$service->result['binding']['data_entry_signature_ip_capture_status'] = 'captured';
$service->result['binding']['data_entry_signature_ip_ciphertext'] = 'EIP1.encrypted.data-entry';
$dataEntryNoRevealService = new AdministratorUiEconsentIpService();
$dataEntryNoReveal = (new AdministratorVerificationController($repository, $service, $dataEntryNoRevealService, false))
    ->verify(substr($captureReference, 2));
adminUiAssert(
    $dataEntryNoRevealService->dataEntryRevealArguments === array()
        && ($dataEntryNoReveal['details']['signature_upload_ip'] ?? null) === AdministratorVerificationController::DETAIL_CAPTURED_ENCRYPTED,
    'Administrator data-entry diagnostics exposed an IP address without Database Query Tool access.'
);
$dataEntryRevealService = new AdministratorUiEconsentIpService();
$dataEntryRevealed = (new AdministratorVerificationController($repository, $service, $dataEntryRevealService, true))
    ->verify(substr($captureReference, 2));
adminUiAssert(
    $dataEntryRevealService->dataEntryRevealArguments === array(true)
        && ($dataEntryRevealed['details']['signature_upload_ip'] ?? null) === '203.0.113.27'
        && !isset($dataEntryRevealed['details']['econsent_submission_ip']),
    'Administrator data-entry diagnostics did not reveal only the authorized upload IP.'
);
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
adminUiAssert(!array_key_exists('documentation', $controlCenterLinks[0]), 'Administrator link contains an unsupported documentation configuration key.');
adminUiAssert($controlCenterLinks[0]['show-header-and-footer'] === true, 'Administrator verification page does not request the REDCap layout.');
adminUiAssert(is_file(__DIR__ . '/../docs/administrator-guide.md'), 'Administrator verification documentation file is missing.');

$entrySource = file_get_contents(__DIR__ . '/../pages/admin-verify-signature.php');
$pageSource = file_get_contents(__DIR__ . '/../pages/partials/verification-page.php');
adminUiAssert(strpos($entrySource, "'is_administrator' => true") !== false, 'Administrator verification entry point does not declare administrator scope.');
adminUiAssert(strpos($entrySource, "require __DIR__ . '/partials/verification-page.php'") !== false, 'Administrator verification entry point does not use the shared page partial.');
adminUiAssert(strpos($entrySource, "'documentation_url' => \$module->getUrl('docs/administrator-guide.md')") !== false, 'Administrator verification entry point does not link its administrator guide.');
adminUiAssert(strpos($entrySource, "\$module->framework->tt('ui_administrator_verification_guide_help')") !== false, 'Administrator verification entry point does not retrieve documentation help text from the language file.');
adminUiAssert(strpos($pageSource, 'method="post"') !== false, 'Administrator verification form does not use POST.');
adminUiAssert(strpos($pageSource, 'id="sigwm-verification-documentation"') !== false, 'Administrator verification page does not render its documentation link.');
adminUiAssert(strpos($pageSource, "\$module->framework->tt('ui_documentation_prompt')") !== false, 'Administrator verification page does not retrieve its documentation prompt through the framework.');
adminUiAssert(strpos($pageSource, '\\ExternalModules\\ExternalModules::interpolateLanguageString(') !== false, 'Administrator verification page does not use the raw HTML interpolation workaround.');
adminUiAssert(strpos($pageSource, 'redcap_csrf_token') !== false, 'Administrator verification form is missing the REDCap CSRF token.');
adminUiAssert(strpos($pageSource, 'type="search"') !== false, 'Administrator verification input is not a search control.');
adminUiAssert(strpos($pageSource, 'name="edoc_id"') !== false, 'Administrator edoc lookup input is missing.');
adminUiAssert(strpos($entrySource, 'verifyEdocId') !== false, 'Administrator page does not invoke edoc verification.');
adminUiAssert(strpos($pageSource, '<h4 style="margin-top:0;" class="clearfix">') !== false, 'Administrator verification title does not use the Control Center page style.');
adminUiAssert(strpos($pageSource, 'id="sigwm-verification-result"') !== false, 'Administrator verification result wrapper is missing.');
adminUiAssert(strpos($pageSource, "captureReference.addEventListener('search'") !== false, 'Administrator search clear handler is missing.');
adminUiAssert(strpos($pageSource, "edocId.addEventListener('search'") !== false, 'Administrator edoc search clear handler is missing.');
adminUiAssert(strpos($pageSource, "result.remove()") !== false, 'Administrator search clear handler does not clear the result.');
adminUiAssert(strpos($pageSource, "\$module->framework->tt('ui_heading_technical_log_history')") !== false, 'Administrator technical history is not translated.');
adminUiAssert(strpos($pageSource, 'JSON_PRETTY_PRINT') !== false, 'Administrator diagnostic details are not pretty-printed.');
adminUiAssert(strpos($pageSource, "\$module->framework->tt('ui_label_log_event')") !== false, 'Administrator diagnostic event row is not translated.');
adminUiAssert(strpos($pageSource, 'border-top: 1px solid #444') !== false, 'Administrator diagnostic entries are not visibly separated.');
adminUiAssert(strpos($pageSource, "\$module->framework->tt('ui_link_go_to_field')") !== false, 'Administrator details do not include a translated field-navigation link.');

echo "Watermarked Signatures administrator UI smoke tests passed.\n";
