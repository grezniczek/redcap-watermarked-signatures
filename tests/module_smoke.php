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
    class Design
    {
        public static function isDraftPreview()
        {
            return false;
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

    ob_start();
    invokePrivate($module, 'intercept_signature_upload');
    echo "<script>window.parent.window.stopUpload(1,'participant_signature','98137','signature.png','',417,'','','',1,true);</script>";
    ob_end_flush();
    $response = ob_get_clean();

    $watermarkedPng = base64_decode($_POST['myfile_base64'], true);
    $info = getimagesizefromstring($watermarkedPng);
    moduleAssert($info[0] === 460 && $info[1] === 158, 'Upload interceptor did not replace the PNG.');
    moduleAssert(count($module->logs) === 1 && $module->logs[0][0] === 'sigwm_upload', 'Upload provenance was not logged.');
    moduleAssert($module->logs[0][1]['edoc_id'] === 98137, 'The returned edoc ID was not captured.');
    moduleAssert(strpos($response, "stopUpload(1,'participant_signature','98137'") !== false, 'The iframe response was altered.');

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
