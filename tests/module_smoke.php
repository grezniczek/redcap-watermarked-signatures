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

    class FakeFramework
    {
        public function getUrl($file)
        {
            return '/modules/watermarked_signatures/' . $file;
        }
    }

    class FakeProject
    {
        public $metadata;
        public $metadata_temp = array();
        private $repeatType;

        public function __construct($repeatType = null, $includeSecondSignature = false)
        {
            $this->repeatType = $repeatType;
            $this->metadata = array(
                'participant_signature' => array(
                    'form_name' => 'consent',
                    'element_type' => 'file',
                    'element_validation_type' => 'signature',
                    'misc' => '@WATERMARKED-SIGNATURE'
                )
            );
            if ($includeSecondSignature) {
                $this->metadata['witness_signature'] = array(
                    'form_name' => 'consent',
                    'element_type' => 'file',
                    'element_validation_type' => 'enhanced_signature',
                    'misc' => '@WATERMARKED-SIGNATURE'
                );
            }
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
            return $this->repeatType === 'event';
        }

        public function isRepeatingForm($eventId, $instrument)
        {
            return $this->repeatType === 'instrument';
        }
    }

    require_once __DIR__ . '/../WatermarkedSignaturesExternalModule.php';

    use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\Anchor;
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

    function invokePrivate($object, $name, $arguments = array())
    {
        $method = new ReflectionMethod($object, $name);
        $method->setAccessible(true);
        return $method->invokeArgs($object, $arguments);
    }

    function uploadProvenance($field, $edocId)
    {
        $scope = array(
            'v' => 1,
            'pid' => 123,
            'event_id' => 417,
            'instrument' => 'consent',
            'field' => $field
        );
        return array(
            'v' => 1,
            'capture_ref' => ReferenceGenerator::captureReference(),
            'context_ref' => ReferenceGenerator::contextReference(),
            'record_ref' => null,
            'anchor' => Anchor::create($scope, KeyDerivation::derive(KeyDerivation::ANCHOR_INFO)),
            'pid' => 123,
            'event_id' => 417,
            'instrument' => 'consent',
            'field' => $field,
            'edoc_id' => $edocId,
            'captured_at' => '2026-07-17T10:00:00Z',
            'file_sha256' => hash('sha256', "test-edoc-{$edocId}"),
            'envelope_nonce' => ReferenceGenerator::nonce(),
            'watermark_version' => 1
        );
    }

    function payloadsForMessage($module, $message)
    {
        $payloads = array();
        foreach ($module->logs as $log) {
            if ($log[0] === $message) {
                $payloads[] = json_decode($log[1]['payload_json'], true);
            }
        }
        return $payloads;
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

    $multiEnvelopeModule = new WatermarkedSignaturesExternalModule();
    $multiEnvelopeModule->framework = new FakeFramework();
    setPrivateProperty($multiEnvelopeModule, 'proj', new FakeProject(null, true));
    setPrivateProperty($multiEnvelopeModule, 'project_id', 123);
    ob_start();
    invokePrivate($multiEnvelopeModule, 'inject_capture_envelopes', array('consent', 417));
    $multiEnvelopeHtml = ob_get_clean();
    moduleAssert(
        preg_match('/window\.REDCapSignatureWatermark=(\{.*?\});<\/script>/s', $multiEnvelopeHtml, $configMatch) === 1,
        'Per-field envelope configuration was not injected.'
    );
    $multiEnvelopeConfig = json_decode($configMatch[1], true);
    moduleAssert(count($multiEnvelopeConfig['envelopes']) === 2, 'Multiple configured signature fields did not receive separate envelopes.');
    $participantEnvelope = $signer->verify($multiEnvelopeConfig['envelopes']['participant_signature']);
    $witnessEnvelope = $signer->verify($multiEnvelopeConfig['envelopes']['witness_signature']);
    moduleAssert($participantEnvelope['field'] === 'participant_signature', 'Participant envelope was scoped to the wrong field.');
    moduleAssert($witnessEnvelope['field'] === 'witness_signature', 'Witness envelope was scoped to the wrong field.');
    moduleAssert($participantEnvelope['context_ref'] !== $witnessEnvelope['context_ref'], 'Signature fields shared a context reference.');

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
    moduleAssert($storedBinding['anchor'] === $uploadProvenance['anchor'], 'Binding did not retain the visible anchor.');
    moduleAssert($module->logs[1][1]['anchor'] === $uploadProvenance['anchor'], 'Binding anchor is not directly inspectable in the log.');
    moduleAssert($storedBinding['repeat_instance'] === null, 'Classic binding did not normalize repeat context.');
    moduleAssert(isset($storedBinding['binding_mac']), 'Binding MAC was not stored.');

    $module->redcap_save_record(123, 'R-001', 'consent', 417, null, null, null, 1);
    moduleAssert(count($module->logs) === 2, 'Repeated save appended a duplicate binding.');

    $repeatInstrumentModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($repeatInstrumentModule, 'proj', new FakeProject('instrument'));
    setPrivateProperty($repeatInstrumentModule, 'project_id', 123);
    $repeatInstrumentModule->append_upload_provenance(uploadProvenance('participant_signature', 98138));
    REDCap::$data = array(
        'R-REPEAT' => array(
            'repeat_instances' => array(417 => array('consent' => array(3 => array('participant_signature' => '98138'))))
        )
    );
    $repeatInstrumentModule->redcap_save_record(123, 'R-REPEAT', 'consent', 417, null, null, null, 3);
    $repeatInstrumentBinding = payloadsForMessage($repeatInstrumentModule, 'sigwm_bind')[0];
    moduleAssert($repeatInstrumentBinding['repeat_type'] === 'instrument', 'Repeating instrument was not bound with its repeat type.');
    moduleAssert($repeatInstrumentBinding['repeat_instrument'] === 'consent', 'Repeating instrument name was not bound.');
    moduleAssert($repeatInstrumentBinding['repeat_instance'] === 3, 'Repeating instrument instance was not bound.');

    $repeatEventModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($repeatEventModule, 'proj', new FakeProject('event'));
    setPrivateProperty($repeatEventModule, 'project_id', 123);
    $repeatEventModule->append_upload_provenance(uploadProvenance('participant_signature', 98139));
    REDCap::$data = array(
        'R-EVENT' => array(
            'repeat_instances' => array(417 => array('' => array(4 => array('participant_signature' => '98139'))))
        )
    );
    $repeatEventModule->redcap_save_record(123, 'R-EVENT', 'consent', 417, null, null, null, 4);
    $repeatEventBinding = payloadsForMessage($repeatEventModule, 'sigwm_bind')[0];
    moduleAssert($repeatEventBinding['repeat_type'] === 'event', 'Repeating event was not bound with its repeat type.');
    moduleAssert($repeatEventBinding['repeat_instrument'] === null, 'Repeating event incorrectly stored an instrument.');
    moduleAssert($repeatEventBinding['repeat_instance'] === 4, 'Repeating event instance was not bound.');

    $abandonedModule = new WatermarkedSignaturesExternalModule();
    $abandonedModule->append_upload_provenance(uploadProvenance('participant_signature', 98999));
    moduleAssert(count(payloadsForMessage($abandonedModule, 'sigwm_upload')) === 1, 'Abandoned upload provenance was not retained.');
    moduleAssert(count(payloadsForMessage($abandonedModule, 'sigwm_bind')) === 0, 'An upload was bound without a successful form save.');

    $lifecycleModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($lifecycleModule, 'proj', new FakeProject(null, true));
    setPrivateProperty($lifecycleModule, 'project_id', 123);
    $lifecycleModule->append_upload_provenance(uploadProvenance('participant_signature', 99001));
    $lifecycleModule->append_upload_provenance(uploadProvenance('participant_signature', 99002));
    $lifecycleModule->append_upload_provenance(uploadProvenance('witness_signature', 99003));
    REDCap::$data = array(
        'R-MULTI' => array(417 => array(
            'participant_signature' => '99002',
            'witness_signature' => '99003'
        ))
    );
    $lifecycleModule->redcap_save_record(123, 'R-MULTI', 'consent', 417, null, null, null, 1);
    $lifecycleBindings = payloadsForMessage($lifecycleModule, 'sigwm_bind');
    $boundEdocs = array_map(function ($binding) { return $binding['edoc_id']; }, $lifecycleBindings);
    sort($boundEdocs);
    moduleAssert($boundEdocs === array(99002, 99003), 'Save did not bind exactly the two persisted signature fields.');
    moduleAssert(!in_array(99001, $boundEdocs, true), 'A superseded pre-save upload was bound.');

    $logCountAfterFirstSave = count($lifecycleModule->logs);
    $lifecycleModule->redcap_save_record(123, 'R-MULTI', 'consent', 417, null, null, null, 1);
    moduleAssert(count($lifecycleModule->logs) === $logCountAfterFirstSave, 'Repeated multi-field save was not idempotent.');

    REDCap::$data = array(
        'R-MULTI' => array(417 => array('participant_signature' => '', 'witness_signature' => ''))
    );
    $lifecycleModule->redcap_save_record(123, 'R-MULTI', 'consent', 417, null, null, null, 1);
    moduleAssert(count($lifecycleModule->logs) === $logCountAfterFirstSave, 'Clearing signature fields altered historical bindings.');

    $lifecycleModule->append_upload_provenance(uploadProvenance('participant_signature', 99004));
    REDCap::$data = array(
        'R-MULTI' => array(417 => array(
            'participant_signature' => '99004',
            'witness_signature' => '99003'
        ))
    );
    $lifecycleModule->redcap_save_record(123, 'R-MULTI', 'consent', 417, null, null, null, 1);
    $replacementBindings = payloadsForMessage($lifecycleModule, 'sigwm_bind');
    $replacementEdocs = array_map(function ($binding) { return $binding['edoc_id']; }, $replacementBindings);
    sort($replacementEdocs);
    moduleAssert($replacementEdocs === array(99002, 99003, 99004), 'A later replacement did not preserve old bindings and bind the new edoc.');

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
