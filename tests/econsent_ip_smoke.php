<?php

namespace {
    class System
    {
        public static $ip = null;

        public static function clientIpAddress()
        {
            return self::$ip;
        }
    }

    class Econsent
    {
        public static $enabled = true;
        public static $archive = null;

        public static function econsentEnabledForSurvey($surveyId)
        {
            return self::$enabled;
        }

        public static function getAttributesOfStoredConsentForm($record, $eventId, $surveyId, $instance)
        {
            return self::$archive;
        }
    }
}

namespace DE\RUB\WatermarkedSignaturesExternalModule\Tests {

require_once __DIR__ . '/../classes/Crypto/Base64Url.php';
require_once __DIR__ . '/../classes/Crypto/CanonicalJson.php';
require_once __DIR__ . '/../classes/Crypto/IpCipher.php';
require_once __DIR__ . '/../classes/Econsent/IpService.php';

use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\IpCipher;
use DE\RUB\WatermarkedSignaturesExternalModule\Econsent\IpService;
use RuntimeException;

function econsentIpAssert($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$cipher = new IpCipher(str_repeat('k', 32));
$service = new IpService($cipher);
$project = (object) array('forms' => array(
    'consent' => array('survey_id' => 715)
));
$captureReference = 'S:1111-2222-3333-4';

$GLOBALS['pdf_econsent_system_ip'] = '1';
\System::$ip = '203.0.113.25';
\Econsent::$enabled = true;
$captured = $service->capture($project, 123, 417, 'consent', 'participant_signature', 'survey', $captureReference);
econsentIpAssert($captured['econsent_survey_id'] === 715, 'e-Consent survey ID was not captured.');
econsentIpAssert($captured['econsent_ip_system_setting_enabled'] === true, 'The e-Consent IP system setting was not snapshotted.');
econsentIpAssert($captured['econsent_ip_capture_status'] === IpService::STATUS_CAPTURED, 'e-Consent signature IP was not captured.');
econsentIpAssert(IpService::isValidCaptureContext($captured), 'Captured e-Consent IP context failed validation.');
econsentIpAssert(strpos($captured['econsent_signature_ip_ciphertext'], '203.0.113.25') === false, 'The signature IP was stored in plaintext.');
econsentIpAssert(
    $cipher->decrypt(
        $captured['econsent_signature_ip_ciphertext'],
        IpService::associatedData(123, 417, 'consent', 'participant_signature', $captureReference)
    ) === '203.0.113.25',
    'Encrypted signature IP could not be restored with its binding context.'
);

$wrongScopeWasRejected = false;
try {
    $cipher->decrypt(
        $captured['econsent_signature_ip_ciphertext'],
        IpService::associatedData(123, 417, 'consent', 'other_signature', $captureReference)
    );
} catch (\Throwable $exception) {
    $wrongScopeWasRejected = true;
}
econsentIpAssert($wrongScopeWasRejected, 'Encrypted signature IP could be moved to another field scope.');

$notApplicable = $service->capture($project, 123, 417, 'consent', 'participant_signature', 'data_entry', $captureReference);
econsentIpAssert(
    $notApplicable['econsent_ip_capture_status'] === IpService::STATUS_NOT_APPLICABLE
        && $notApplicable['econsent_signature_ip_ciphertext'] === null,
    'Non-survey signatures incorrectly retained e-Consent IP data.'
);

$GLOBALS['pdf_econsent_system_ip'] = '0';
$disabled = $service->capture($project, 123, 417, 'consent', 'participant_signature', 'survey', $captureReference);
econsentIpAssert(
    $disabled['econsent_ip_capture_status'] === IpService::STATUS_SYSTEM_DISABLED
        && $disabled['econsent_ip_system_setting_enabled'] === false
        && $disabled['econsent_signature_ip_ciphertext'] === null,
    'Disabled e-Consent IP capture did not retain an explicit not-captured state.'
);

$GLOBALS['pdf_econsent_system_ip'] = '1';
$binding = array_merge(array(
    'v' => 3,
    'pid' => 123,
    'event_id' => 417,
    'instrument' => 'consent',
    'field' => 'participant_signature',
    'capture_ref' => $captureReference,
    'record_id' => 'R-001',
    'repeat_instance' => 1
), $captured);
\Econsent::$archive = array('ip' => '203.0.113.25');
$matched = $service->compare($binding, 'R-001', false);
econsentIpAssert($matched['status'] === 'match' && $matched['warning'] === false, 'Matching e-Consent IPs were not recognized.');
econsentIpAssert(!isset($matched['signature_upload_ip']) && !isset($matched['econsent_submission_ip']), 'Project-safe comparison revealed IP addresses.');

\Econsent::$archive = array('ip' => '203.0.113.26');
$mismatched = $service->compare($binding, 'R-001', true);
econsentIpAssert(
    $mismatched['status'] === 'mismatch'
        && $mismatched['warning'] === true
        && $mismatched['signature_upload_ip'] === '203.0.113.25'
        && $mismatched['econsent_submission_ip'] === '203.0.113.26',
    'Administrator e-Consent IP mismatch diagnostics did not return the forensic values.'
);

\System::$ip = '2001:db8::1';
$ipv6Capture = $service->capture($project, 123, 417, 'consent', 'participant_signature', 'survey', 'S:5555-6666-7777-8');
$ipv6Binding = array_merge($binding, $ipv6Capture, array('capture_ref' => 'S:5555-6666-7777-8'));
\Econsent::$archive = array('ip' => '2001:0DB8:0:0:0:0:0:1');
econsentIpAssert(
    $service->compare($ipv6Binding, 'R-001', false)['status'] === 'match',
    'Equivalent IPv6 address representations produced an e-Consent IP mismatch.'
);

$notTested = $service->compare(array_merge($binding, $disabled), 'R-001', false);
econsentIpAssert(
    $notTested['status'] === 'not_tested_system_disabled' && $notTested['warning'] === false,
    'Disabled e-Consent IP capture did not report comparison as not tested.'
);

echo "Watermarked Signatures e-Consent IP smoke tests passed.\n";

}
