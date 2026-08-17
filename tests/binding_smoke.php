<?php

namespace {
    if (!defined('MYSQLI_STORE_RESULT')) {
        define('MYSQLI_STORE_RESULT', 0);
    }

    // LogRepository deliberately calls REDCap's global database helper.
    if (!function_exists('db_query_throw_on_error')) {
        function db_query_throw_on_error($sql, $parameters = array(), $connection = null, $resultMode = MYSQLI_STORE_RESULT, $forcePrimary = false)
        {
            \DE\RUB\WatermarkedSignaturesExternalModule\Tests\bindingAssert($forcePrimary === true, 'Binding query did not force REDCap primary DB routing.');
            $GLOBALS['bindingPrimaryQueryCount']++;
            $module = $GLOBALS['bindingPrimaryModule'];
            \DE\RUB\WatermarkedSignaturesExternalModule\Tests\bindingAssert($module !== null, 'Primary-query smoke test has no active module.');

            if (strpos($sql, 'where message = ?') !== false) {
                $GLOBALS['bindingPrimaryLogQueryCount']++;
                return $module->queryLogs($sql, $parameters);
            }
            return $module->query($sql, $parameters);
        }
    }
}

namespace DE\RUB\WatermarkedSignaturesExternalModule\Tests {

require_once __DIR__ . '/../classes/Crypto/Base64Url.php';
require_once __DIR__ . '/../classes/Crypto/CanonicalJson.php';
require_once __DIR__ . '/../classes/Crypto/BindingMac.php';
require_once __DIR__ . '/../classes/Context/SavedContext.php';
require_once __DIR__ . '/../classes/Storage/LogRepository.php';

use DE\RUB\WatermarkedSignaturesExternalModule\Context\SavedContext;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\Base64Url;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\BindingMac;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\CanonicalJson;
use DE\RUB\WatermarkedSignaturesExternalModule\Storage\LogRepository;
use RuntimeException;

function bindingAssert($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$GLOBALS['bindingPrimaryModule'] = null;
$GLOBALS['bindingPrimaryQueryCount'] = 0;
$GLOBALS['bindingPrimaryLogQueryCount'] = 0;

class BindingTestProject
{
    private $repeatType;

    public function __construct($repeatType)
    {
        $this->repeatType = $repeatType;
    }

    public function isRepeatingEvent($eventId)
    {
        return $this->repeatType === 'event';
    }

    public function isRepeatingForm($eventId, $instrument)
    {
        return $this->repeatType === 'instrument';
    }
}

class BindingTestResult
{
    private $row;

    public function __construct($row)
    {
        $this->row = $row;
    }

    public function fetch_assoc()
    {
        $row = $this->row;
        $this->row = null;
        return $row;
    }

    public function fetch_row()
    {
        $row = $this->row;
        $this->row = null;
        return $row;
    }
}

class BindingTestModule
{
    public $events = array();
    public $lockAcquired = true;
    public $releaseCount = 0;
    public $lockNames = array();
    public $lastLogQuery = null;

    public function query($sql, $parameters)
    {
        if (strpos($sql, 'GET_LOCK') !== false) {
            $this->lockNames[] = $parameters[0];
            return new BindingTestResult(array($this->lockAcquired ? 1 : 0));
        }
        if (strpos($sql, 'RELEASE_LOCK') !== false) {
            $this->releaseCount++;
            return new BindingTestResult(array(1));
        }
        throw new RuntimeException('Unexpected query in binding test.');
    }

    public function queryLogs($sql, $parameters)
    {
        $this->lastLogQuery = $sql;
        if (strpos($sql, 'envelope_nonce_hash = ?') !== false) {
            list($message, $nonceHash) = $parameters;
            foreach ($this->events as $event) {
                if ($event['message'] === $message
                    && hash_equals((string) ($event['parameters']['envelope_nonce_hash'] ?? ''), (string) $nonceHash)) {
                    return new BindingTestResult(array('log_id' => $event['log_id']));
                }
            }
            return new BindingTestResult(null);
        }
        if (strpos($sql, 'record = ?') !== false) {
            list($message, $record) = $parameters;
            foreach ($this->events as $event) {
                if ($event['message'] === $message && (string) ($event['parameters']['record'] ?? '') === (string) $record) {
                    return new BindingTestResult(array(
                        'log_id' => $event['log_id'],
                        'record' => $event['parameters']['record']
                    ));
                }
            }
            return new BindingTestResult(null);
        }
        list($message, $edocId) = $parameters;
        foreach ($this->events as $event) {
            if ($event['message'] === $message && (int) $event['edoc_id'] === (int) $edocId) {
                return new BindingTestResult(array(
                    'log_id' => $event['log_id'],
                    'payload_json' => $event['payload_json']
                ));
            }
        }
        return new BindingTestResult(null);
    }

    public function getQueryLogsSql($sql)
    {
        return $sql;
    }

    public function log($message, $parameters)
    {
        $this->events[] = array(
            'log_id' => count($this->events) + 1,
            'message' => $message,
            'edoc_id' => isset($parameters['edoc_id']) ? (int) $parameters['edoc_id'] : 0,
            'payload_json' => $parameters['payload_json'] ?? null,
            'parameters' => $parameters
        );
        return count($this->events);
    }
}

$classic = new SavedContext(new BindingTestProject(null), 123, 'R-001', 'consent', 417, 1);
$classicData = array('R-001' => array(417 => array('sig_a' => '1001', 'sig_b' => '1002')));
bindingAssert($classic->extractFieldValues($classicData, array('sig_a', 'sig_b')) === array('sig_a' => '1001', 'sig_b' => '1002'), 'Classic saved context extraction failed.');
bindingAssert($classic->bindingValues('sig_a')['repeat_instance'] === null, 'Classic context must bind an explicit null repeat instance.');

$repeatEvent = new SavedContext(new BindingTestProject('event'), 123, 'R-001', 'consent', 417, 3);
$repeatEventData = array(
    'R-001' => array('repeat_instances' => array(417 => array('' => array(3 => array('sig_a' => '2001')))))
);
bindingAssert($repeatEvent->extractFieldValues($repeatEventData, array('sig_a'))['sig_a'] === '2001', 'Repeating-event extraction failed.');
bindingAssert($repeatEvent->bindingValues('sig_a')['repeat_type'] === 'event', 'Repeating-event type was not normalized.');

$repeatForm = new SavedContext(new BindingTestProject('instrument'), 123, 'R-001', 'consent', 417, 4);
$repeatFormData = array(
    'R-001' => array('repeat_instances' => array(417 => array('consent' => array(4 => array('sig_a' => '3001')))))
);
bindingAssert($repeatForm->extractFieldValues($repeatFormData, array('sig_a'))['sig_a'] === '3001', 'Repeating-instrument extraction failed.');
bindingAssert($repeatForm->bindingValues('sig_a')['repeat_instrument'] === 'consent', 'Repeating instrument was not normalized.');

$binding = array(
    'v' => 1,
    'anchor' => 'A:AAAA-BBBB-CCCC-DDDD',
    'capture_ref' => 'S:1111-2222-3333-4',
    'context_ref' => 'C:1111-2222-3333-4',
    'record_ref' => null,
    'project_reference' => null,
    'capture_origin' => 'data_entry',
    'capture_username' => 'capture-user',
    'save_origin' => 'data_entry',
    'save_username' => 'save-user',
    'record_id' => 'R-001',
    'pid' => 123,
    'event_id' => 417,
    'instrument' => 'consent',
    'field' => 'sig_a',
    'repeat_type' => null,
    'repeat_instrument' => null,
    'repeat_instance' => null,
    'edoc_id' => 98137,
    'bound_at' => '2026-07-17T08:00:00.000Z',
    'file_sha256' => str_repeat('a', 64),
    'watermark_version' => 1
);

$mac = new BindingMac(str_repeat('b', 32));
$bindingWithMac = $binding;
$bindingWithMac['binding_mac'] = $mac->create($bindingWithMac);
bindingAssert($mac->verify($bindingWithMac), 'Binding MAC verification failed.');
$tamperedBinding = $bindingWithMac;
$tamperedBinding['record_id'] = 'R-002';
bindingAssert(!$mac->verify($tamperedBinding), 'Binding MAC did not detect a changed record.');
$tamperedAnchorBinding = $bindingWithMac;
$tamperedAnchorBinding['anchor'] = 'A:EEEE-FFFF-GGGG-HHHH';
bindingAssert(!$mac->verify($tamperedAnchorBinding), 'Binding MAC did not detect a changed anchor.');
$tamperedOriginBinding = $bindingWithMac;
$tamperedOriginBinding['capture_origin'] = 'survey';
bindingAssert(!$mac->verify($tamperedOriginBinding), 'Binding MAC did not detect a changed capture origin.');
$tamperedUsernameBinding = $bindingWithMac;
$tamperedUsernameBinding['save_username'] = 'other-user';
bindingAssert(!$mac->verify($tamperedUsernameBinding), 'Binding MAC did not detect a changed username snapshot.');

// Format v2 keeps this base MAC deliberately compatible with the v1.0.2
// verifier and protects field_reference with an independently derived MAC.
$v2Mac = new BindingMac(str_repeat('b', 32), str_repeat('c', 32));
$v2Binding = $binding;
$v2Binding['v'] = 2;
$v2Binding['field_reference'] = 'CONSENT';
$v2Binding['binding_mac'] = $v2Mac->create($v2Binding);
$v2Binding['binding_extension_mac'] = $v2Mac->createExtension($v2Binding);
bindingAssert($v2Mac->verify($v2Binding), 'Format-v2 binding base MAC verification failed.');
bindingAssert($v2Mac->verifyExtension($v2Binding), 'Format-v2 binding extension MAC verification failed.');
$v102Verifier = new BindingMac(str_repeat('b', 32));
bindingAssert($v102Verifier->verify($v2Binding), 'A v1.0.2-compatible base verifier rejected a format-v2 binding.');
$tamperedV2FieldReference = $v2Binding;
$tamperedV2FieldReference['field_reference'] = 'WITHDRAWN';
bindingAssert($v2Mac->verify($tamperedV2FieldReference), 'Changing only a format-v2 extension unexpectedly changed the base MAC.');
bindingAssert(!$v2Mac->verifyExtension($tamperedV2FieldReference), 'Extension MAC did not detect a changed field reference.');

// Format v3 adds encrypted e-Consent-IP capture context under a third,
// independently derived MAC while preserving the prior base and field-
// reference extension formats for compatibility.
$v3Mac = new BindingMac(str_repeat('b', 32), str_repeat('c', 32), str_repeat('d', 32));
$v3Binding = $binding;
$v3Binding['v'] = 3;
$v3Binding['field_reference'] = 'CONSENT';
$v3Binding['econsent_survey_id'] = 715;
$v3Binding['econsent_ip_system_setting_enabled'] = true;
$v3Binding['econsent_ip_capture_status'] = 'captured';
$v3Binding['econsent_signature_ip_ciphertext'] = 'EIP1.MTIzNDU2Nzg5MDEy.MTIzNDU2Nzg5MDEyMzQ1Ng.c2lnbmF0dXJlLWlw';
$v3Binding['binding_mac'] = $v3Mac->create($v3Binding);
$v3Binding['binding_extension_mac'] = $v3Mac->createExtension($v3Binding);
$v3Binding['binding_econsent_ip_mac'] = $v3Mac->createEconsentIpExtension($v3Binding);
bindingAssert($v3Mac->verify($v3Binding), 'Format-v3 binding base MAC verification failed.');
bindingAssert($v3Mac->verifyExtension($v3Binding), 'Format-v3 field-reference extension MAC verification failed.');
bindingAssert($v3Mac->verifyEconsentIpExtension($v3Binding), 'Format-v3 e-Consent-IP MAC verification failed.');
bindingAssert($v102Verifier->verify($v3Binding), 'A v1.0.2-compatible base verifier rejected a format-v3 binding.');
$tamperedV3Ip = $v3Binding;
$tamperedV3Ip['econsent_signature_ip_ciphertext'] = 'EIP1.MTIzNDU2Nzg5MDEy.MTIzNDU2Nzg5MDEyMzQ1Ng.dGFtcGVyZWQ';
bindingAssert($v3Mac->verify($tamperedV3Ip), 'Changing only v3 IP context unexpectedly changed the base MAC.');
bindingAssert($v3Mac->verifyExtension($tamperedV3Ip), 'Changing only v3 IP context unexpectedly changed the field-reference extension MAC.');
bindingAssert(!$v3Mac->verifyEconsentIpExtension($tamperedV3Ip), 'e-Consent-IP MAC did not detect a changed ciphertext.');

// Accept the short-lived development format that included field_reference in
// the v1 base-MAC payload before the released v2 extension format existed.
$preReleaseBinding = $binding;
$preReleaseBinding['field_reference'] = 'CONSENT';
$preReleasePayload = $mac->definingPayload($preReleaseBinding);
$preReleasePayload['field_reference'] = $preReleaseBinding['field_reference'];
$preReleaseBinding['binding_mac'] = Base64Url::encode(hash_hmac(
    'sha256',
    CanonicalJson::encode($preReleasePayload),
    str_repeat('b', 32),
    true
));
bindingAssert($mac->verify($preReleaseBinding), 'Pre-release field-reference binding did not remain verifiable.');

$module = new BindingTestModule();
$GLOBALS['bindingPrimaryModule'] = $module;
$repository = new LogRepository($module, $mac);
bindingAssert($repository->bindOnce($binding) === LogRepository::RESULT_BOUND, 'First binding was not appended.');
bindingAssert($module->events[0]['parameters']['anchor'] === $binding['anchor'], 'Binding log did not expose the anchor parameter.');
bindingAssert($module->events[0]['parameters']['capture_origin'] === 'data_entry', 'Binding log did not expose the capture origin.');
bindingAssert($module->events[0]['parameters']['save_origin'] === 'data_entry', 'Binding log did not expose the save origin.');
bindingAssert($repository->bindOnce($binding) === LogRepository::RESULT_IDEMPOTENT, 'Identical binding was not idempotent.');
bindingAssert(count(array_filter($module->events, function ($event) { return $event['message'] === 'sigwm_bind'; })) === 1, 'Idempotent binding appended a duplicate.');
$laterSave = $binding;
$laterSave['save_origin'] = 'survey';
$laterSave['save_username'] = null;
bindingAssert($repository->bindOnce($laterSave) === LogRepository::RESULT_IDEMPOTENT, 'A later save through another channel was not idempotent.');
bindingAssert(count($module->events) === 1, 'A later save through another channel appended an audit error for an existing binding.');

$conflicting = $binding;
$conflicting['record_id'] = 'R-002';
$conflicting['pid'] = 999;
bindingAssert($repository->bindOnce($conflicting) === LogRepository::RESULT_CONFLICT, 'Conflicting binding was not rejected.');
bindingAssert(end($module->events)['message'] === 'sigwm_error_edoc_already_bound', 'Binding conflict did not append the expected error.');
bindingAssert(count(array_unique($module->lockNames)) === 1, 'The edoc lock incorrectly changes between projects.');
bindingAssert(strpos($module->lastLogQuery, 'project_id >= 0') !== false, 'Binding lookup is not global across projects.');

foreach ($module->events as &$event) {
    if ($event['message'] === 'sigwm_bind') {
        $stored = json_decode($event['payload_json'], true);
        $stored['binding_mac'] = str_repeat('x', 43);
        $event['payload_json'] = json_encode($stored);
        break;
    }
}
unset($event);
bindingAssert($repository->bindOnce($binding) === LogRepository::RESULT_INVALID_EXISTING_MAC, 'Invalid existing MAC was not detected.');
bindingAssert(end($module->events)['message'] === 'sigwm_error_binding_mac', 'Invalid binding MAC did not append the expected error.');
bindingAssert($module->releaseCount === 5, 'A binding lock was not released.');
bindingAssert($GLOBALS['bindingPrimaryQueryCount'] > 0, 'Primary database query path was not exercised.');
bindingAssert($GLOBALS['bindingPrimaryLogQueryCount'] > 0, 'Binding lookup did not use the primary database path.');
$primaryLogQueriesBeforeRenameLookup = $GLOBALS['bindingPrimaryLogQueryCount'];
bindingAssert($repository->findBoundRecordId('R-001') === 'R-001', 'Bound record lookup did not return the current record ID.');
bindingAssert($GLOBALS['bindingPrimaryLogQueryCount'] === $primaryLogQueriesBeforeRenameLookup + 1, 'Bound record lookup did not use the primary database path.');

$v2Module = new BindingTestModule();
$GLOBALS['bindingPrimaryModule'] = $v2Module;
$v2Repository = new LogRepository($v2Module, $v2Mac);
bindingAssert($v2Repository->bindOnce($v2Binding) === LogRepository::RESULT_BOUND, 'Format-v2 binding was not appended.');
$storedV2Binding = json_decode($v2Module->events[0]['payload_json'], true);
bindingAssert(isset($storedV2Binding['binding_extension_mac']), 'Format-v2 binding did not store its extension MAC.');
bindingAssert($v2Mac->verifyExtension($storedV2Binding), 'Stored format-v2 extension MAC did not verify.');
$conflictingV2FieldReference = $v2Binding;
$conflictingV2FieldReference['field_reference'] = 'WITHDRAWN';
bindingAssert($v2Repository->bindOnce($conflictingV2FieldReference) === LogRepository::RESULT_CONFLICT, 'A changed format-v2 field reference was treated as idempotent.');
$storedV2Binding['binding_extension_mac'] = str_repeat('x', 43);
$v2Module->events[0]['payload_json'] = json_encode($storedV2Binding);
bindingAssert($v2Repository->bindOnce($v2Binding) === LogRepository::RESULT_INVALID_EXISTING_MAC, 'Invalid existing extension MAC was not detected.');

$v3Module = new BindingTestModule();
$GLOBALS['bindingPrimaryModule'] = $v3Module;
$v3Repository = new LogRepository($v3Module, $v3Mac);
bindingAssert($v3Repository->bindOnce($v3Binding) === LogRepository::RESULT_BOUND, 'Format-v3 binding was not appended.');
$storedV3Binding = json_decode($v3Module->events[0]['payload_json'], true);
bindingAssert(isset($storedV3Binding['binding_econsent_ip_mac']), 'Format-v3 binding did not store its e-Consent-IP MAC.');
bindingAssert($v3Mac->verifyEconsentIpExtension($storedV3Binding), 'Stored format-v3 e-Consent-IP MAC did not verify.');
bindingAssert(
    strpos($v3Module->events[0]['payload_json'], '203.0.113.25') === false
        && !in_array($v3Binding['econsent_signature_ip_ciphertext'], $v3Module->events[0]['parameters'], true),
    'Format-v3 binding exposed e-Consent IP evidence outside its encrypted payload.'
);
$tamperedStoredV3Binding = $storedV3Binding;
$tamperedStoredV3Binding['binding_econsent_ip_mac'] = str_repeat('x', 43);
$v3Module->events[0]['payload_json'] = json_encode($tamperedStoredV3Binding);
bindingAssert($v3Repository->bindOnce($v3Binding) === LogRepository::RESULT_INVALID_EXISTING_MAC, 'Invalid existing e-Consent-IP MAC was not detected.');

$nonceModule = new BindingTestModule();
$GLOBALS['bindingPrimaryModule'] = $nonceModule;
$nonceRepository = new LogRepository($nonceModule, $mac);
$nonce = str_repeat('a', 32);
bindingAssert($nonceRepository->reserveEnvelopeNonce($nonce) === true, 'First envelope nonce reservation was not accepted.');
bindingAssert($nonceRepository->reserveEnvelopeNonce($nonce) === false, 'Replayed envelope nonce was not rejected.');
bindingAssert(count($nonceModule->events) === 1, 'Replayed envelope nonce appended another log entry.');
bindingAssert(
    $nonceModule->events[0]['parameters']['envelope_nonce_hash'] === hash('sha256', $nonce),
    'Envelope nonce reservation did not store the nonce hash.'
);
bindingAssert(
    !in_array($nonce, $nonceModule->events[0]['parameters'], true),
    'Envelope nonce reservation stored the raw nonce.'
);
bindingAssert($nonceModule->releaseCount === 2, 'Envelope nonce locks were not released.');
bindingAssert(strlen($nonceModule->lockNames[0]) <= 64, 'Envelope nonce lock name exceeds MySQL\'s limit.');

$mismatchModule = new BindingTestModule();
$GLOBALS['bindingPrimaryModule'] = $mismatchModule;
$mismatchRepository = new LogRepository($mismatchModule, $mac);
$originMismatch = $binding;
$originMismatch['capture_origin'] = 'survey';
bindingAssert($mismatchRepository->bindOnce($originMismatch) === LogRepository::RESULT_ORIGIN_MISMATCH, 'First-binding origin mismatch was not rejected.');
bindingAssert($mismatchModule->events[0]['message'] === 'sigwm_error_origin_mismatch', 'Origin mismatch did not append its dedicated error event.');
bindingAssert($mismatchModule->events[0]['parameters']['capture_origin'] === 'survey', 'Origin mismatch log did not expose the capture origin.');
bindingAssert($mismatchModule->events[0]['parameters']['save_origin'] === 'data_entry', 'Origin mismatch log did not expose the save origin.');
bindingAssert(count(array_filter($mismatchModule->events, function ($event) { return $event['message'] === 'sigwm_bind'; })) === 0, 'Origin mismatch appended a binding.');

$lockedModule = new BindingTestModule();
$lockedModule->lockAcquired = false;
$GLOBALS['bindingPrimaryModule'] = $lockedModule;
$lockedRepository = new LogRepository($lockedModule, $mac);
$lockFailed = false;
try {
    $lockedRepository->bindOnce($binding);
} catch (RuntimeException $exception) {
    $lockFailed = true;
}
bindingAssert($lockFailed, 'Binding continued after lock acquisition timed out.');

echo "Watermarked Signatures binding smoke tests passed.\n";
}
