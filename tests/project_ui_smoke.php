<?php

require_once __DIR__ . '/../classes/Crypto/Base32.php';
require_once __DIR__ . '/../classes/Crypto/Base64Url.php';
require_once __DIR__ . '/../classes/Crypto/ReferenceGenerator.php';
require_once __DIR__ . '/../classes/Verification/ProjectAccessPolicy.php';
require_once __DIR__ . '/../classes/Verification/ProjectVerificationController.php';

use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\ProjectAccessPolicy;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\ProjectVerificationController;

class UserRights
{
    public static function convertFormRightsToArray($rightsString)
    {
        $rights = array();
        if (preg_match_all('/\[([^,\]]+),([^\]]+)\]/', (string) $rightsString, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $rights[$match[1]] = $match[2];
            }
        }
        return $rights;
    }

    public static function hasDataViewingRights($value, $right)
    {
        if ($right !== 'no-access') {
            throw new RuntimeException('Unsupported test right.');
        }
        if (!is_numeric($value) || $value === '') {
            return true;
        }
        $value = (int) $value;
        return $value < 128 ? $value === 0 : $value === 128;
    }
}

function projectUiAssert($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

class ProjectUiRepository
{
    public $upload;
    public $binding;

    public function findUploadByCaptureReference($captureReference, $projectId)
    {
        return $this->upload;
    }

    public function findBindingByEdocId($edocId)
    {
        return $this->binding;
    }
}

class ProjectUiMac
{
    public $valid = true;

    public function verify($binding)
    {
        return $this->valid;
    }
}

class ProjectUiService
{
    public $calls = 0;
    public $result;
    public $lastReference;

    public function verify($captureReference, $projectId)
    {
        $this->calls++;
        $this->lastReference = $captureReference;
        return $this->result;
    }
}

function projectUiResult($captureReference)
{
    return array(
        'status' => 'valid_current',
        'binding_state' => 'bound',
        'integrity' => 'valid',
        'current_state' => 'current',
        'capture_ref' => $captureReference,
        'current_record_id' => 'R-002',
        'checks' => array('binding_mac' => true, 'current_field' => true),
        'issues' => array(),
        'edoc' => array('exists' => true, 'readable' => true, 'doc_name' => 'signature.png'),
        'upload' => array(
            'capture_ref' => $captureReference,
            'context_ref' => 'C-1111-2222-3333-4',
            'anchor' => 'AAAA-BBBB-CCCC-DDDD',
            'capture_origin' => 'data_entry',
            'capture_username' => 'capture-user',
            'captured_at' => '2026-07-17T13:00:00Z',
            'edoc_id' => 98137,
            'file_sha256' => str_repeat('a', 64),
            'project_reference' => 'SIGWM-TEST',
            'envelope_nonce' => 'must-not-be-presented',
            'pid' => 123,
            'instrument' => 'consent'
        ),
        'binding' => array(
            'record_id' => 'R-001',
            'event_id' => 417,
            'instrument' => 'consent',
            'field' => 'participant_signature',
            'repeat_type' => null,
            'repeat_instrument' => null,
            'repeat_instance' => null,
            'bound_at' => '2026-07-17T13:01:00.000Z',
            'save_origin' => 'data_entry',
            'save_username' => 'save-user',
            'watermark_version' => 1,
            'binding_mac' => 'must-not-be-presented',
            'pid' => 123
        )
    );
}

$noAccess = new ProjectAccessPolicy(123, false, array(
    'data_entry' => '[consent,128][other,138]',
    'group_id' => ''
), function ($record) { return null; });
projectUiAssert(!$noAccess->canViewInstrument('consent'), 'No-access form right was accepted.');
projectUiAssert(!$noAccess->canViewInstrument('missing'), 'Missing form right was accepted.');

$readOnly = new ProjectAccessPolicy(123, false, array(
    'data_entry' => '[consent,2][other,0]',
    'group_id' => ''
), function ($record) { return null; });
projectUiAssert($readOnly->canViewInstrument('consent'), 'Legacy read-only form right was rejected.');
projectUiAssert($readOnly->canAccessAnyInstrument(array('other', 'consent')), 'Accessible configured form did not enable the page.');

$bitmaskReadOnly = new ProjectAccessPolicy(123, false, array(
    'data_entry' => '[consent,129][other,138]',
    'group_id' => ''
), function ($record) { return null; });
projectUiAssert($bitmaskReadOnly->canViewInstrument('consent'), 'Bitmask read-only form right was rejected.');
projectUiAssert($bitmaskReadOnly->canViewInstrument('other'), 'Bitmask view/edit form right was rejected.');

$superUser = new ProjectAccessPolicy(123, true, array('group_id' => 99), function ($record) { return 1; });
projectUiAssert($superUser->canViewInstrument('consent') && !$superUser->isDagRestricted(), 'Superuser access was incorrectly restricted.');

$dagPolicy = new ProjectAccessPolicy(123, false, array(
    'data_entry' => '[consent,138]',
    'group_id' => 7
), function ($record) {
    return $record === 'R-001' ? 7 : 8;
});
$binding = array('pid' => 123, 'instrument' => 'consent', 'record_id' => 'R-001');
projectUiAssert($dagPolicy->canViewBinding($binding), 'Matching DAG binding was rejected.');
$binding['record_id'] = 'R-OTHER';
projectUiAssert(!$dagPolicy->canViewBinding($binding), 'Binding from another DAG was accepted.');

$captureReference = ReferenceGenerator::captureReference();
$repository = new ProjectUiRepository();
$repository->upload = array(
    'capture_ref' => $captureReference,
    'edoc_id' => 98137,
    'pid' => 123,
    'instrument' => 'consent'
);
$repository->binding = array(
    'edoc_id' => 98137,
    'pid' => 123,
    'instrument' => 'consent',
    'record_id' => 'R-001',
    '_current_record_id' => 'R-002'
);
$mac = new ProjectUiMac();
$service = new ProjectUiService();
$service->result = projectUiResult($captureReference);
$allowedPolicy = new ProjectAccessPolicy(123, false, array(
    'data_entry' => '[consent,129]',
    'group_id' => ''
), function ($record) { return null; });
$controller = new ProjectVerificationController(123, $repository, $mac, $service, $allowedPolicy);
$presented = $controller->verify($captureReference);
projectUiAssert($presented['status'] === 'valid_current' && $service->calls === 1, 'Authorized verification was not delegated to the service.');
projectUiAssert($presented['details']['record_id'] === 'R-002', 'Authorized record details did not show the current record ID.');
projectUiAssert($presented['details']['project_reference'] === 'SIGWM-TEST', 'Authorized details did not show the public project reference.');
projectUiAssert(!isset($presented['upload']) && !isset($presented['binding']), 'Raw verification payload escaped the project presenter.');
projectUiAssert(!isset($presented['details']['envelope_nonce']) && !isset($presented['details']['binding_mac']), 'Sensitive technical values escaped the allowlist.');
$printedReference = substr($captureReference, 2);
$controller->verify($printedReference);
projectUiAssert($service->lastReference === $captureReference, 'Printed capture reference was not normalized to the internal form.');
projectUiAssert(ReferenceGenerator::normalizeCaptureReference('s:' . strtolower($printedReference)) === $captureReference, 'S:-prefixed printed reference was not normalized.');

$deniedController = new ProjectVerificationController(123, $repository, $mac, $service, $noAccess);
$callsBeforeDenial = $service->calls;
projectUiAssert($deniedController->verify($captureReference)['status'] === 'access_denied', 'Form-rights denial was not enforced.');
projectUiAssert($service->calls === $callsBeforeDenial, 'Denied form access invoked full verification.');

$otherDagPolicy = new ProjectAccessPolicy(123, false, array(
    'data_entry' => '[consent,138]',
    'group_id' => 8
), function ($record) { return $record === 'R-002' ? 8 : 7; });
$otherDagController = new ProjectVerificationController(123, $repository, $mac, $service, $otherDagPolicy);
projectUiAssert($otherDagController->verify($captureReference)['status'] === 'valid_current', 'Current record ID was not used for DAG authorization.');

$repository->binding = null;
$dagUnboundController = new ProjectVerificationController(123, $repository, $mac, $service, $dagPolicy);
projectUiAssert($dagUnboundController->verify($captureReference)['status'] === 'access_denied', 'DAG-restricted user received an unbound upload result.');
$service->result['status'] = 'unbound';
$service->result['binding_state'] = 'unbound';
$service->result['binding'] = null;
$unrestrictedUnboundController = new ProjectVerificationController(123, $repository, $mac, $service, $allowedPolicy);
projectUiAssert($unrestrictedUnboundController->verify($captureReference)['status'] === 'unbound', 'Project-wide user could not inspect an unbound upload.');

$repository->binding = array(
    'edoc_id' => 98137,
    'pid' => 123,
    'instrument' => 'consent',
    'record_id' => 'R-001'
);
$mac->valid = false;
$invalidMacResult = $controller->verify($captureReference);
projectUiAssert($invalidMacResult['status'] === 'invalid' && empty($invalidMacResult['details']), 'Untrusted binding details were exposed.');

$config = json_decode(file_get_contents(__DIR__ . '/../config.json'), true);
projectUiAssert(is_array($config), 'config.json is invalid JSON.');
$projectLinks = $config['links']['project'] ?? array();
projectUiAssert(count($projectLinks) === 1 && $projectLinks[0]['key'] === 'signature-verification', 'Project verification link is not configured.');
projectUiAssert($projectLinks[0]['show-header-and-footer'] === true, 'Project verification page does not request the REDCap layout.');

$entrySource = file_get_contents(__DIR__ . '/../pages/verify-signature.php');
$pageSource = file_get_contents(__DIR__ . '/../pages/partials/verification-page.php');
projectUiAssert(strpos($entrySource, "'is_administrator' => false") !== false, 'Project verification entry point does not declare project scope.');
projectUiAssert(strpos($entrySource, "require __DIR__ . '/partials/verification-page.php'") !== false, 'Project verification entry point does not use the shared page partial.');
projectUiAssert(strpos($pageSource, 'method="post"') !== false, 'Verification form does not use POST.');
projectUiAssert(strpos($pageSource, 'redcap_csrf_token') !== false, 'Verification form is missing the REDCap CSRF token.');
projectUiAssert(strpos($pageSource, 'type="search"') !== false, 'Verification input is not a search control.');
projectUiAssert(strpos($pageSource, '<span class="input-group-text">S:</span>') !== false, 'Verification input does not show the printed S: prefix.');
projectUiAssert(strpos($pageSource, 'placeholder="5622-9F1F-AHCA-K"') !== false, 'Verification placeholder does not match the printed reference format.');
projectUiAssert(strpos($pageSource, '<h1 class="projhdr">') !== false, 'Project verification title does not use the project-page style.');
projectUiAssert(strpos($pageSource, "captureReference.addEventListener('search'") !== false, 'Verification search clear handler is missing.');
projectUiAssert(strpos($pageSource, 'id="sigwm-verification-result"') !== false, 'Verification result wrapper is missing.');
projectUiAssert(strpos($pageSource, "result.remove()") !== false, 'Verification search clear handler does not clear the result.');

echo "Watermarked Signatures project UI smoke tests passed.\n";
