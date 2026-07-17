<?php

require_once __DIR__ . '/../classes/Crypto/Base32.php';
require_once __DIR__ . '/../classes/Crypto/Base64Url.php';
require_once __DIR__ . '/../classes/Crypto/CanonicalJson.php';
require_once __DIR__ . '/../classes/Crypto/KeyDerivation.php';
require_once __DIR__ . '/../classes/Crypto/ReferenceGenerator.php';
require_once __DIR__ . '/../classes/Crypto/Anchor.php';
require_once __DIR__ . '/../classes/Crypto/BindingMac.php';
require_once __DIR__ . '/../classes/Storage/LogRepository.php';
require_once __DIR__ . '/../classes/Verification/RedcapEdocReader.php';
require_once __DIR__ . '/../classes/Verification/RedcapCurrentValueReader.php';
require_once __DIR__ . '/../classes/Verification/VerificationService.php';

use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\Anchor;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\BindingMac;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\CanonicalJson;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\KeyDerivation;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
use DE\RUB\WatermarkedSignaturesExternalModule\Storage\LogRepository;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\RedcapCurrentValueReader;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\RedcapEdocReader;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\VerificationService;

function verificationAssert($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

class VerificationResult
{
    private $rows;

    public function __construct($rows)
    {
        $this->rows = array_values($rows);
    }

    public function fetch_assoc()
    {
        return empty($this->rows) ? null : array_shift($this->rows);
    }
}

class VerificationModule
{
    public $events = array();
    public $queryCount = 0;

    public function addEvent($message, $payload, $projectId = 123, $record = null)
    {
        $this->events[] = array(
            'log_id' => count($this->events) + 1,
            'message' => $message,
            'project_id' => $projectId,
            'record' => $record === null ? ($payload['record_id'] ?? ($payload['new_record_id'] ?? '')) : (string) $record,
            'payload_json' => CanonicalJson::encode($payload)
        );
    }

    public function queryLogs($sql, $parameters)
    {
        $this->queryCount++;
        if (strpos($sql, 'previous_record_id') !== false && strpos($sql, 'record = ?') !== false) {
            list($message, $projectId, $recordId) = $parameters;
            $rows = array();
            foreach ($this->events as $event) {
                if ($event['message'] !== $message
                    || (int) $event['project_id'] !== (int) $projectId
                    || (string) $event['record'] !== (string) $recordId) {
                    continue;
                }
                $payload = json_decode($event['payload_json'], true);
                $rows[] = array(
                    'log_id' => $event['log_id'],
                    'timestamp' => '2026-07-17 20:00:07',
                    'username' => 'verification-user',
                    'project_id' => $event['project_id'],
                    'record' => $event['record'],
                    'message' => $event['message'],
                    'previous_record_id' => $payload['old_record_id'] ?? null,
                    'rename_origin' => $payload['rename_origin'] ?? null,
                    'rename_username' => $payload['rename_username'] ?? null,
                    'renamed_at' => $payload['renamed_at'] ?? null
                );
            }
            return new VerificationResult($rows);
        }
        if (strpos($sql, 'where edoc_id = ?') !== false) {
            $edocId = (int) $parameters[0];
            $rows = array();
            foreach ($this->events as $event) {
                $payload = json_decode($event['payload_json'], true);
                if ((int) ($payload['edoc_id'] ?? 0) !== $edocId) {
                    continue;
                }
                $rows[] = array_merge(array(
                    'log_id' => $event['log_id'],
                    'timestamp' => '2026-07-17 13:02:15',
                    'username' => 'verification-user',
                    'project_id' => $event['project_id'],
                    'record' => $event['record'],
                    'message' => $event['message']
                ), $payload);
            }
            return new VerificationResult($rows);
        }

        $message = $parameters[0];
        $target = $parameters[1];
        $byCaptureReference = strpos($sql, 'capture_ref = ?') !== false;
        $projectId = strpos($sql, 'project_id = ?') !== false ? (int) $parameters[2] : null;
        $rows = array();

        foreach ($this->events as $event) {
            if ($event['message'] !== $message || ($projectId !== null && $event['project_id'] !== $projectId)) {
                continue;
            }
            $payload = json_decode($event['payload_json'], true);
            $matches = $byCaptureReference
                ? (($payload['capture_ref'] ?? null) === $target)
                : ((int) ($payload['edoc_id'] ?? 0) === (int) $target);
            if ($matches) {
                $rows[] = array(
                    'log_id' => $event['log_id'],
                    'payload_json' => $event['payload_json'],
                    'project_id' => $event['project_id'],
                    'record' => $event['record']
                );
            }
        }
        return new VerificationResult(array_slice($rows, 0, 2));
    }
}

class VerificationEdocReader
{
    public $files = array();

    public function read($edocId, $projectId)
    {
        if (!isset($this->files[$edocId])) {
            return array('exists' => false, 'readable' => false, 'contents' => null);
        }
        return $this->files[$edocId];
    }
}

class VerificationCurrentValueReader
{
    public $value = null;
    public $fail = false;
    public $lastBinding = null;

    public function read($binding)
    {
        $this->lastBinding = $binding;
        if ($this->fail) {
            throw new RuntimeException('Synthetic current-value read failure.');
        }
        return $this->value;
    }
}

class REDCap
{
    public static $data = array();

    public static function getData($parameters)
    {
        return self::$data;
    }
}

class Files
{
    public static $info = array();
    public static $attributes = array();

    public static function getEdocInfo($edocId, $projectId, $includeDeleted)
    {
        if (!isset(self::$info[$edocId]) || (int) self::$info[$edocId]['project_id'] !== (int) $projectId) {
            return null;
        }
        return self::$info[$edocId];
    }

    public static function getEdocContentsAttributes($edocId)
    {
        return self::$attributes[$edocId] ?? false;
    }
}

function verificationUpload($captureReference, $edocId, $bytes)
{
    $scope = array(
        'v' => 1,
        'pid' => 123,
        'event_id' => 417,
        'instrument' => 'consent',
        'field' => 'participant_signature'
    );
    return array(
        'v' => 1,
        'anchor' => Anchor::create($scope, KeyDerivation::derive(KeyDerivation::ANCHOR_INFO)),
        'capture_ref' => $captureReference,
        'context_ref' => ReferenceGenerator::contextReference(),
        'record_ref' => null,
        'capture_origin' => 'data_entry',
        'capture_username' => 'capture-user',
        'edoc_id' => $edocId,
        'pid' => 123,
        'event_id' => 417,
        'instrument' => 'consent',
        'field' => 'participant_signature',
        'captured_at' => '2026-07-17T13:00:00Z',
        'file_sha256' => hash('sha256', $bytes),
        'envelope_nonce' => 'abcdefghijklmnopqrstuvwxyz',
        'watermark_version' => 1
    );
}

function verificationBinding($upload, BindingMac $mac)
{
    $binding = array(
        'v' => 1,
        'anchor' => $upload['anchor'],
        'capture_ref' => $upload['capture_ref'],
        'context_ref' => $upload['context_ref'],
        'record_ref' => $upload['record_ref'],
        'capture_origin' => $upload['capture_origin'],
        'capture_username' => $upload['capture_username'],
        'save_origin' => 'data_entry',
        'save_username' => 'save-user',
        'record_id' => 'R-001',
        'pid' => $upload['pid'],
        'event_id' => $upload['event_id'],
        'instrument' => $upload['instrument'],
        'field' => $upload['field'],
        'repeat_type' => null,
        'repeat_instrument' => null,
        'repeat_instance' => null,
        'edoc_id' => $upload['edoc_id'],
        'bound_at' => '2026-07-17T13:01:00.000Z',
        'file_sha256' => $upload['file_sha256'],
        'watermark_version' => $upload['watermark_version']
    );
    $binding['binding_mac'] = $mac->create($binding);
    return $binding;
}

function verificationHarness($upload, $binding, $bytes)
{
    $module = new VerificationModule();
    $module->addEvent('sigwm_upload', $upload);
    if ($binding !== null) {
        $module->addEvent('sigwm_bind', $binding);
    }
    $mac = new BindingMac(KeyDerivation::derive(KeyDerivation::BINDING_INFO));
    $edocs = new VerificationEdocReader();
    $edocs->files[$upload['edoc_id']] = array(
        'exists' => true,
        'readable' => true,
        'contents' => $bytes,
        'mime_type' => 'image/png',
        'doc_name' => 'signature.png'
    );
    $current = new VerificationCurrentValueReader();
    $current->value = (string) $upload['edoc_id'];
    $service = new VerificationService(new LogRepository($module, $mac), $mac, $edocs, $current);
    return array($service, $module, $edocs, $current);
}

$GLOBALS['salt'] = 'redcap-test-installation-salt';
$GLOBALS['salt2'] = 'redcap-test-installation-salt-2';
$mac = new BindingMac(KeyDerivation::derive(KeyDerivation::BINDING_INFO));
$bytes = 'final-watermarked-png-bytes';
$captureReference = ReferenceGenerator::captureReference();
$upload = verificationUpload($captureReference, 98137, $bytes);
$binding = verificationBinding($upload, $mac);

list($service, $module, $edocs, $current) = verificationHarness($upload, $binding, $bytes);
$valid = $service->verify($captureReference, 123);
verificationAssert($valid['status'] === 'valid_current', 'Valid current signature did not verify.');
verificationAssert($valid['binding_state'] === 'bound' && $valid['integrity'] === 'valid', 'Valid verification state was not structured correctly.');
verificationAssert($valid['checks']['binding_mac'] === true, 'Binding MAC was not verified.');
verificationAssert($valid['checks']['binding_upload'] === true, 'Binding was not matched to upload provenance.');
verificationAssert($valid['checks']['anchor'] === true, 'Stable-scope anchor was not recomputed.');
verificationAssert($valid['checks']['edoc_exists'] === true && $valid['checks']['file_digest'] === true, 'Edoc integrity was not verified.');
verificationAssert($valid['checks']['current_field'] === true, 'Current field was not compared with the bound edoc.');
verificationAssert(!array_key_exists('contents', $valid['edoc']), 'Verification result exposed edoc bytes.');
verificationAssert($service->verify($captureReference, null)['status'] === 'valid_current', 'Administrator exact lookup did not span projects.');
verificationAssert($service->verify($captureReference, 999)['status'] === 'unknown', 'Project-scoped lookup exposed another project.');
$history = (new LogRepository($module, $mac))->findDiagnosticEventsByEdocId(98137);
verificationAssert(count($history) === 2, 'Administrator diagnostic lookup did not return upload and binding history.');
verificationAssert($history[0]['message'] === 'sigwm_upload' && $history[1]['message'] === 'sigwm_bind', 'Administrator diagnostic lookup returned an unexpected history.');
verificationAssert(!array_key_exists('payload_json', $history[0]), 'Administrator diagnostic lookup returned raw payload JSON.');

$renamedReference = ReferenceGenerator::captureReference();
$renamedUpload = verificationUpload($renamedReference, 98139, $bytes);
$renamedBinding = verificationBinding($renamedUpload, $mac);
list($renamedService, $renamedModule, , $renamedCurrent) = verificationHarness($renamedUpload, $renamedBinding, $bytes);
// REDCap updates the EM log row's indexed record value during a rename while
// the MAC-protected payload retains the historical binding-time value.
$renamedModule->events[1]['record'] = 'R-002';
$renamedModule->addEvent('sigwm_record_rename', array(
    'v' => 1,
    'pid' => 123,
    'old_record_id' => 'R-001',
    'new_record_id' => 'R-002',
    'rename_origin' => 'data_entry_record_home',
    'rename_username' => 'rename-user',
    'renamed_at' => '2026-07-17T20:00:07.906Z'
), 123, 'R-002');
$renamed = $renamedService->verify($renamedReference, 123);
verificationAssert($renamed['status'] === 'valid_current', 'Record rename caused the live field check to fail.');
verificationAssert($renamed['current_record_id'] === 'R-002', 'Verification did not expose the current record ID.');
verificationAssert($renamedCurrent->lastBinding['record_id'] === 'R-002', 'Live field lookup used the historical record ID after rename.');
$renameHistory = (new LogRepository($renamedModule, $mac))->findRecordRenameEventsByCurrentRecord(123, 'R-002');
verificationAssert(count($renameHistory) === 1 && $renameHistory[0]['previous_record_id'] === 'R-001', 'Current record rename history was not found.');

$current->value = '98138';
verificationAssert($service->verify($captureReference, 123)['status'] === 'valid_historical', 'Historical signature was not distinguished from the current value.');

$unknownReference = ReferenceGenerator::captureReference();
verificationAssert($service->verify($unknownReference, 123)['status'] === 'unknown', 'Unknown capture reference was not reported.');
$queriesBeforeInvalidReference = $module->queryCount;
verificationAssert($service->verify('S-not-valid', 123)['status'] === 'invalid_reference', 'Malformed capture reference was not rejected.');
verificationAssert($module->queryCount === $queriesBeforeInvalidReference, 'Malformed reference triggered a log lookup.');

$unboundReference = ReferenceGenerator::captureReference();
$unboundUpload = verificationUpload($unboundReference, 98138, $bytes);
list($unboundService) = verificationHarness($unboundUpload, null, $bytes);
$unbound = $unboundService->verify($unboundReference, 123);
verificationAssert($unbound['status'] === 'unbound' && $unbound['binding_state'] === 'unbound', 'Unbound upload was not reported.');
verificationAssert($unbound['checks']['file_digest'] === true, 'Unbound upload edoc integrity was not checked.');

$invalidMacBinding = $binding;
$invalidMacBinding['binding_mac'] = str_repeat('x', 43);
list($invalidMacService) = verificationHarness($upload, $invalidMacBinding, $bytes);
$invalidMac = $invalidMacService->verify($captureReference, 123);
verificationAssert($invalidMac['status'] === 'invalid' && in_array('binding_mac_mismatch', $invalidMac['issues'], true), 'Invalid binding MAC was not detected.');

$anchorUpload = $upload;
$anchorUpload['anchor'] = 'AAAA-BBBB-CCCC-DDDD';
$anchorBinding = verificationBinding($anchorUpload, $mac);
list($anchorService) = verificationHarness($anchorUpload, $anchorBinding, $bytes);
$anchorResult = $anchorService->verify($captureReference, 123);
verificationAssert($anchorResult['status'] === 'invalid' && in_array('anchor_mismatch', $anchorResult['issues'], true), 'Anchor mismatch was not detected.');

list($digestService, , $digestEdocs) = verificationHarness($upload, $binding, 'altered-edoc-bytes');
$digestResult = $digestService->verify($captureReference, 123);
verificationAssert($digestResult['status'] === 'invalid' && in_array('file_digest_mismatch', $digestResult['issues'], true), 'Final edoc digest mismatch was not detected.');

list($missingService, , $missingEdocs) = verificationHarness($upload, $binding, $bytes);
unset($missingEdocs->files[$upload['edoc_id']]);
$missingResult = $missingService->verify($captureReference, 123);
verificationAssert($missingResult['status'] === 'incomplete' && in_array('edoc_missing', $missingResult['issues'], true), 'Missing edoc was not reported as incomplete.');

$mismatchedBinding = $binding;
$mismatchedBinding['capture_username'] = 'different-capture-user';
$mismatchedBinding['binding_mac'] = $mac->create($mismatchedBinding);
list($relationshipService) = verificationHarness($upload, $mismatchedBinding, $bytes);
$relationshipResult = $relationshipService->verify($captureReference, 123);
verificationAssert($relationshipResult['status'] === 'invalid' && in_array('binding_upload_mismatch', $relationshipResult['issues'], true), 'Binding/upload relationship mismatch was not detected.');

list($currentFailureService, , , $failingCurrentReader) = verificationHarness($upload, $binding, $bytes);
$failingCurrentReader->fail = true;
$currentFailure = $currentFailureService->verify($captureReference, 123);
verificationAssert($currentFailure['status'] === 'incomplete' && in_array('current_field_unreadable', $currentFailure['issues'], true), 'Current-field read failure was not reported.');

$duplicateModule = new VerificationModule();
$duplicateModule->addEvent('sigwm_upload', $upload);
$duplicateModule->addEvent('sigwm_upload', $upload);
$duplicateRepository = new LogRepository($duplicateModule, $mac);
$duplicateRejected = false;
try {
    $duplicateRepository->findUploadByCaptureReference($captureReference, 123);
} catch (RuntimeException $exception) {
    $duplicateRejected = true;
}
verificationAssert($duplicateRejected, 'Duplicate capture references were silently accepted.');

$redcapEdocReader = new RedcapEdocReader();
Files::$info[99001] = array('project_id' => 123, 'mime_type' => 'image/png', 'doc_name' => 'signature.png');
Files::$attributes[99001] = array('image/png', 'signature.png', 'stored-bytes');
$redcapEdoc = $redcapEdocReader->read(99001, 123);
verificationAssert($redcapEdoc['exists'] && $redcapEdoc['readable'] && $redcapEdoc['contents'] === 'stored-bytes', 'REDCap edoc adapter did not read through Files.');
verificationAssert($redcapEdocReader->read(99001, 999)['exists'] === false, 'REDCap edoc adapter did not enforce project ownership.');

$currentValueReader = new RedcapCurrentValueReader();
$classicBinding = $binding;
REDCap::$data = array('R-001' => array(417 => array('participant_signature' => '98137')));
verificationAssert($currentValueReader->read($classicBinding) === '98137', 'Classic current field lookup failed.');
$repeatInstrumentBinding = $binding;
$repeatInstrumentBinding['repeat_type'] = 'instrument';
$repeatInstrumentBinding['repeat_instrument'] = 'consent';
$repeatInstrumentBinding['repeat_instance'] = 3;
REDCap::$data = array('R-001' => array('repeat_instances' => array(417 => array('consent' => array(3 => array('participant_signature' => '98137'))))));
verificationAssert($currentValueReader->read($repeatInstrumentBinding) === '98137', 'Repeating-instrument current field lookup failed.');
$repeatEventBinding = $binding;
$repeatEventBinding['repeat_type'] = 'event';
$repeatEventBinding['repeat_instrument'] = null;
$repeatEventBinding['repeat_instance'] = 4;
REDCap::$data = array('R-001' => array('repeat_instances' => array(417 => array('' => array(4 => array('participant_signature' => '98137'))))));
verificationAssert($currentValueReader->read($repeatEventBinding) === '98137', 'Repeating-event current field lookup failed.');

echo "Watermarked Signatures verification smoke tests passed.\n";
