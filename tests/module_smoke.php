<?php

namespace ExternalModules {
    class AbstractExternalModule
    {
        public $framework;
        public $logs = array();
        public $exitRequested = false;

        public function getProjectSetting($key)
        {
            return false;
        }

        public function log($message, $parameters = array())
        {
            $this->logs[] = array($message, $parameters);
            return count($this->logs);
        }

        public function query($sql, $parameters = array())
        {
            if (strpos($sql, 'GET_LOCK') !== false || strpos($sql, 'RELEASE_LOCK') !== false) {
                return new \FakeModuleResult(array(1));
            }
            throw new \RuntimeException('Unexpected module query in smoke test.');
        }

        public function queryLogs($sql, $parameters = array())
        {
            list($message, $edocId) = $parameters;
            foreach ($this->logs as $index => $log) {
                if ($log[0] === $message && (int) ($log[1]['edoc_id'] ?? 0) === (int) $edocId) {
                    return new \FakeModuleResult(array(
                        'log_id' => $index + 1,
                        'payload_json' => $log[1]['payload_json'],
                        'project_id' => 123
                    ));
                }
            }
            return new \FakeModuleResult(null);
        }

        public function exitAfterHook()
        {
            $this->exitRequested = true;
        }

        public function getModulePath()
        {
            return dirname(__DIR__) . '/';
        }
    }
}

namespace {
    class FakeModuleResult
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

    class Design
    {
        public static function isDraftPreview()
        {
            return false;
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

    class FakeProject
    {
        public $metadata;
        public $metadata_temp = array();

        public function __construct()
        {
            $this->metadata = array(
                'participant_signature' => array(
                    'form_name' => 'consent',
                    'element_type' => 'file',
                    'element_validation_type' => 'signature',
                    'misc' => '@WATERMARKED-SIGNATURE'
                )
            );
        }

        public function validateEventId($eventId)
        {
            return $eventId === 417;
        }

        public function validateFormEvent($instrument, $eventId)
        {
            return $instrument === 'consent' && $eventId === 417;
        }

        public function isRepeatingEvent($eventId)
        {
            return false;
        }

        public function isRepeatingForm($eventId, $instrument)
        {
            return false;
        }
    }

    require_once __DIR__ . '/../WatermarkedSignaturesExternalModule.php';

    use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\EnvelopeSigner;
    use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\KeyDerivation;
    use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
    use DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule;

    function moduleAssert($condition, $message)
    {
        if (!$condition) {
            throw new RuntimeException($message);
        }
    }

    function setPrivateProperty($object, $name, $value)
    {
        $property = new ReflectionProperty($object, $name);
        $property->setAccessible(true);
        $property->setValue($object, $value);
    }

    function invokePrivate($object, $name)
    {
        $method = new ReflectionMethod($object, $name);
        $method->setAccessible(true);
        return $method->invoke($object);
    }

    $GLOBALS['salt'] = 'redcap-test-installation-salt';
    $GLOBALS['salt2'] = 'redcap-test-installation-salt-2';

    $image = imagecreatetruecolor(460, 120);
    $white = imagecolorallocate($image, 255, 255, 255);
    $black = imagecolorallocate($image, 0, 0, 0);
    imagefilledrectangle($image, 0, 0, 460, 120, $white);
    imageline($image, 30, 80, 420, 40, $black);
    ob_start();
    imagepng($image);
    $originalPng = ob_get_clean();
    imagedestroy($image);

    $module = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($module, 'proj', new FakeProject());
    setPrivateProperty($module, 'project_id', 123);

    $now = time();
    $payload = array(
        'v' => 1,
        'pid' => 123,
        'event_id' => 417,
        'instrument' => 'consent',
        'field' => 'participant_signature',
        'context_ref' => ReferenceGenerator::contextReference(),
        'record_ref' => null,
        'issued_at' => $now,
        'expires_at' => $now + 3600,
        'nonce' => ReferenceGenerator::nonce(),
        'purpose' => 'signature'
    );
    $signer = new EnvelopeSigner(KeyDerivation::derive(KeyDerivation::ENVELOPE_INFO));

    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_GET = array('event_id' => '417', 'instance' => '1');
    $_POST = array(
        'field_name' => 'participant_signature-linknew',
        'sigwm_envelope' => $signer->sign($payload),
        'myfile_base64' => base64_encode($originalPng)
    );

    // Reproduce the framework's hook output wrapper. It closes the topmost
    // buffer after the module returns, which must consume only our guard.
    ob_start();
    ob_start();
    invokePrivate($module, 'intercept_signature_upload');
    echo ob_get_clean();
    moduleAssert(count($module->logs) === 0, 'Provenance was recorded before REDCap returned an edoc ID.');
    echo "<script>window.parent.window.stopUpload(1,'participant_signature','98137','signature.png','',417,'','','',1,true);</script>";
    ob_end_flush();
    ob_end_flush();
    $response = ob_get_clean();

    $watermarkedPng = base64_decode($_POST['myfile_base64'], true);
    $info = getimagesizefromstring($watermarkedPng);
    moduleAssert($info[0] === 460 && $info[1] === 158, 'Upload interceptor did not replace the PNG.');
    moduleAssert(count($module->logs) === 1 && $module->logs[0][0] === 'sigwm_upload', 'Upload provenance was not logged.');
    moduleAssert($module->logs[0][1]['edoc_id'] === 98137, 'The returned edoc ID was not captured.');
    moduleAssert(strpos($response, "stopUpload(1,'participant_signature','98137'") !== false, 'The iframe response was altered.');
    $uploadProvenance = json_decode($module->logs[0][1]['payload_json'], true);
    moduleAssert($uploadProvenance['file_sha256'] === hash('sha256', $watermarkedPng), 'Provenance digest does not cover the final PNG.');
    moduleAssert($uploadProvenance['watermark_version'] === 1, 'Provenance did not retain the WM1 format version.');
    moduleAssert((bool) preg_match('/Z$/', $uploadProvenance['captured_at']), 'Provenance timestamp is not UTC.');

    REDCap::$data = array(
        'R-001' => array(417 => array('participant_signature' => '98137'))
    );
    $module->redcap_save_record(123, 'R-001', 'consent', 417, null, null, null, 1);
    moduleAssert(count($module->logs) === 2 && $module->logs[1][0] === 'sigwm_bind', 'Persisted signature was not bound after save.');
    $storedBinding = json_decode($module->logs[1][1]['payload_json'], true);
    moduleAssert($storedBinding['record_id'] === 'R-001', 'Binding did not contain the authoritative record ID.');
    moduleAssert($storedBinding['repeat_instance'] === null, 'Classic binding did not normalize repeat context.');
    moduleAssert(isset($storedBinding['binding_mac']), 'Binding MAC was not stored.');

    $module->redcap_save_record(123, 'R-001', 'consent', 417, null, null, null, 1);
    moduleAssert(count($module->logs) === 2, 'Repeated save appended a duplicate binding.');

    $scopeMismatchModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($scopeMismatchModule, 'proj', new FakeProject());
    setPrivateProperty($scopeMismatchModule, 'project_id', 123);
    $_GET = array('event_id' => '418', 'instance' => '1');
    $_POST = array(
        'field_name' => 'participant_signature-linknew',
        'sigwm_envelope' => $signer->sign($payload),
        'myfile_base64' => base64_encode($originalPng)
    );

    ob_start();
    invokePrivate($scopeMismatchModule, 'intercept_signature_upload');
    ob_end_clean();
    moduleAssert($scopeMismatchModule->exitRequested, 'An envelope from another request event was accepted.');

    $failedModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($failedModule, 'proj', new FakeProject());
    setPrivateProperty($failedModule, 'project_id', 123);
    $_GET = array('event_id' => '417', 'instance' => '3');
    $_POST = array(
        'field_name' => 'participant_signature-linknew',
        'myfile_base64' => base64_encode($originalPng)
    );

    ob_start();
    invokePrivate($failedModule, 'intercept_signature_upload');
    $failureResponse = ob_get_clean();

    moduleAssert($failedModule->exitRequested, 'Missing envelopes do not fail closed.');
    moduleAssert($failedModule->logs[0][0] === 'sigwm_error_invalid_envelope', 'Missing envelope error was not logged.');
    moduleAssert(strpos($failureResponse, 'could not be securely watermarked') !== false, 'The upload failure response is missing.');
    moduleAssert(strpos($failureResponse, ", 3, true)") !== false, 'The failure response lost the repeat instance.');

    echo "Watermarked Signatures module smoke tests passed.\n";
}
