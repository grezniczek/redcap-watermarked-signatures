<?php

namespace ExternalModules {
    class ExternalModules
    {
        public static $username = null;

        public static function getUsername()
        {
            return self::$username;
        }
    }

    class AbstractExternalModule
    {
        public $framework;
        public $logs = array();
        public $exitRequested = false;
        public $testUser;

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

        public function getUser($username = null)
        {
            return $this->testUser;
        }

        public function getDAG($record)
        {
            return null;
        }

        public function redcap_module_link_check_display($projectId, $link)
        {
            return null;
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

    class FakeUser
    {
        private $superUser;
        private $rights;

        public function __construct($superUser, $rights)
        {
            $this->superUser = $superUser;
            $this->rights = $rights;
        }

        public function isSuperUser()
        {
            return $this->superUser;
        }

        public function getRights($projectId)
        {
            return $this->rights;
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

    function uploadProvenance($field, $edocId, $captureOrigin = 'data_entry', $captureUsername = 'capture-user')
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
            'capture_origin' => $captureOrigin,
            'capture_username' => $captureUsername,
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

    function injectedConfig($html)
    {
        moduleAssert(
            preg_match('/window\.REDCapSignatureWatermark=(\{.*?\});<\/script>/s', $html, $matches) === 1,
            'Signature watermark configuration was not injected.'
        );
        $config = json_decode($matches[1], true);
        moduleAssert(is_array($config), 'Injected signature watermark configuration was invalid.');
        return $config;
    }

    function captureSignatureUpload($module, $envelope, $originalPng, $edocId, $field = 'participant_signature')
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_GET = array('event_id' => '417', 'instance' => '1', 'page' => 'consent');
        $_POST = array(
            'field_name' => $field . '-linknew',
            'sigwm_envelope' => $envelope,
            'myfile_base64' => base64_encode($originalPng)
        );

        ob_start();
        ob_start();
        invokePrivate($module, 'intercept_signature_upload');
        echo ob_get_clean();
        echo "<script>window.parent.window.stopUpload(1,'{$field}','{$edocId}','signature.png','',417,'','','',1,true);</script>";
        ob_end_flush();
        ob_end_flush();
        ob_get_clean();

        $uploads = payloadsForMessage($module, 'sigwm_upload');
        moduleAssert(!empty($uploads), 'Deferred-record signature upload did not create provenance.');
        return $uploads[count($uploads) - 1];
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
        'capture_origin' => 'data_entry',
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
    invokePrivate($multiEnvelopeModule, 'inject_capture_envelopes', array('consent', 417, 'data_entry'));
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

    $verificationLink = array('key' => 'signature-verification', 'url' => 'pages/verify-signature.php');
    $linkModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($linkModule, 'proj', new FakeProject());
    setPrivateProperty($linkModule, 'project_id', 123);
    $linkModule->testUser = new FakeUser(false, array(
        'forms' => array('consent' => '2'),
        'group_id' => ''
    ));
    moduleAssert($linkModule->redcap_module_link_check_display(123, $verificationLink) === $verificationLink, 'Read-only form user did not receive the verification link.');
    $linkModule->testUser = new FakeUser(false, array(
        'forms' => array('consent' => '0'),
        'group_id' => ''
    ));
    moduleAssert($linkModule->redcap_module_link_check_display(123, $verificationLink) === null, 'User without signature-form access received the verification link.');

    $autoNumberModule = new WatermarkedSignaturesExternalModule();
    $autoNumberModule->framework = new FakeFramework();
    setPrivateProperty($autoNumberModule, 'proj', new FakeProject());
    setPrivateProperty($autoNumberModule, 'project_id', 123);
    \ExternalModules\ExternalModules::$username = 'auto-capture-user';
    ob_start();
    $autoNumberModule->redcap_data_entry_form(123, null, 'consent', 417, null, 1);
    $autoNumberHtml = ob_get_clean();
    $autoNumberConfig = injectedConfig($autoNumberHtml);
    $autoNumberEnvelope = $signer->verify($autoNumberConfig['envelopes']['participant_signature']);
    moduleAssert($autoNumberEnvelope['capture_origin'] === 'data_entry', 'Data-entry envelope did not identify its capture origin.');
    moduleAssert($autoNumberEnvelope['record_ref'] === null, 'Tentative auto-number record leaked into the capture envelope.');
    moduleAssert(!array_key_exists('record_id', $autoNumberEnvelope), 'Capture envelope contained a pre-save record ID.');
    $autoNumberUpload = captureSignatureUpload(
        $autoNumberModule,
        $autoNumberConfig['envelopes']['participant_signature'],
        $originalPng,
        99501
    );
    moduleAssert($autoNumberUpload['capture_origin'] === 'data_entry', 'Data-entry upload provenance lost its capture origin.');
    moduleAssert($autoNumberUpload['capture_username'] === 'auto-capture-user', 'Upload provenance did not snapshot the authenticated capture username.');
    moduleAssert(count(payloadsForMessage($autoNumberModule, 'sigwm_bind')) === 0, 'Auto-number upload bound before record creation.');
    REDCap::$data = array(
        '1007' => array(417 => array('participant_signature' => '99501'))
    );
    \ExternalModules\ExternalModules::$username = 'auto-save-user';
    $autoNumberModule->redcap_save_record(123, '1007', 'consent', 417, null, null, null, 1);
    $autoNumberBinding = payloadsForMessage($autoNumberModule, 'sigwm_bind')[0];
    moduleAssert($autoNumberBinding['record_id'] === '1007', 'Auto-number binding did not use REDCap\'s authoritative record ID.');
    moduleAssert($autoNumberBinding['context_ref'] === $autoNumberUpload['context_ref'], 'Auto-number binding lost its pre-save context reference.');
    moduleAssert($autoNumberBinding['record_ref'] === null, 'Deferred record pseudonym was not represented explicitly as null.');
    moduleAssert($autoNumberBinding['capture_origin'] === 'data_entry' && $autoNumberBinding['save_origin'] === 'data_entry', 'Data-entry binding did not retain matching origins.');
    moduleAssert($autoNumberBinding['capture_username'] === 'auto-capture-user', 'Binding lost the capture username snapshot.');
    moduleAssert($autoNumberBinding['save_username'] === 'auto-save-user', 'Binding did not snapshot the save username.');
    moduleAssert($autoNumberModule->logs[1][1]['capture_origin'] === 'data_entry', 'Binding capture origin is not directly inspectable.');
    moduleAssert($autoNumberModule->logs[1][1]['save_origin'] === 'data_entry', 'Binding save origin is not directly inspectable.');
    moduleAssert($autoNumberModule->logs[1][1]['capture_username'] === 'auto-capture-user', 'Binding capture username is not directly inspectable.');
    moduleAssert($autoNumberModule->logs[1][1]['save_username'] === 'auto-save-user', 'Binding save username is not directly inspectable.');

    $surveyModule = new WatermarkedSignaturesExternalModule();
    $surveyModule->framework = new FakeFramework();
    setPrivateProperty($surveyModule, 'proj', new FakeProject());
    setPrivateProperty($surveyModule, 'project_id', 123);
    \ExternalModules\ExternalModules::$username = null;
    ob_start();
    $surveyModule->redcap_survey_page(123, null, 'consent', 417, null, 'public-survey-hash', null, 1);
    $surveyHtml = ob_get_clean();
    $surveyConfig = injectedConfig($surveyHtml);
    $surveyEnvelope = $signer->verify($surveyConfig['envelopes']['participant_signature']);
    moduleAssert($surveyEnvelope['capture_origin'] === 'survey', 'Survey envelope did not identify its capture origin.');
    moduleAssert($surveyEnvelope['record_ref'] === null, 'First-page survey envelope assumed a record ID.');
    moduleAssert(!array_key_exists('record_id', $surveyEnvelope), 'First-page survey envelope exposed a tentative record ID.');
    $surveyUpload = captureSignatureUpload(
        $surveyModule,
        $surveyConfig['envelopes']['participant_signature'],
        $originalPng,
        99502
    );
    moduleAssert($surveyUpload['capture_origin'] === 'survey', 'Survey upload provenance lost its capture origin.');
    moduleAssert($surveyUpload['capture_username'] === null, 'Public survey upload unexpectedly recorded an authenticated username.');
    moduleAssert(count(payloadsForMessage($surveyModule, 'sigwm_bind')) === 0, 'First-page survey upload bound before survey save.');
    REDCap::$data = array(
        'SURVEY-2001' => array(417 => array('participant_signature' => '99502'))
    );
    $surveyModule->redcap_save_record(123, 'SURVEY-2001', 'consent', 417, null, 'public-survey-hash', 7001, 1);
    $surveyBinding = payloadsForMessage($surveyModule, 'sigwm_bind')[0];
    moduleAssert($surveyBinding['record_id'] === 'SURVEY-2001', 'First-page survey binding did not use the created record ID.');
    moduleAssert($surveyBinding['context_ref'] === $surveyUpload['context_ref'], 'First-page survey binding lost its pre-save context reference.');
    moduleAssert($surveyBinding['capture_origin'] === 'survey' && $surveyBinding['save_origin'] === 'survey', 'Survey binding did not retain matching origins.');
    moduleAssert($surveyBinding['capture_username'] === null && $surveyBinding['save_username'] === null, 'Public survey binding unexpectedly recorded an authenticated username.');
    $surveyLogCount = count($surveyModule->logs);
    \ExternalModules\ExternalModules::$username = 'later-staff-user';
    $surveyModule->redcap_save_record(123, 'SURVEY-2001', 'consent', 417, null, null, null, 1);
    moduleAssert(count($surveyModule->logs) === $surveyLogCount, 'A later staff save produced a false origin mismatch for an existing survey binding.');

    $abandonedSurveyModule = new WatermarkedSignaturesExternalModule();
    $abandonedSurveyModule->framework = new FakeFramework();
    setPrivateProperty($abandonedSurveyModule, 'proj', new FakeProject());
    setPrivateProperty($abandonedSurveyModule, 'project_id', 123);
    \ExternalModules\ExternalModules::$username = null;
    ob_start();
    $abandonedSurveyModule->redcap_survey_page(123, null, 'consent', 417, null, 'public-survey-hash', null, 1);
    $abandonedSurveyConfig = injectedConfig(ob_get_clean());
    captureSignatureUpload(
        $abandonedSurveyModule,
        $abandonedSurveyConfig['envelopes']['participant_signature'],
        $originalPng,
        99503
    );
    moduleAssert(count(payloadsForMessage($abandonedSurveyModule, 'sigwm_upload')) === 1, 'Abandoned first-page survey lost upload provenance.');
    moduleAssert(count(payloadsForMessage($abandonedSurveyModule, 'sigwm_bind')) === 0, 'Abandoned first-page survey created a binding.');

    $originMismatchModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($originMismatchModule, 'proj', new FakeProject());
    setPrivateProperty($originMismatchModule, 'project_id', 123);
    $originMismatchModule->append_upload_provenance(
        uploadProvenance('participant_signature', 99504, 'survey', null)
    );
    REDCap::$data = array(
        'ORIGIN-MISMATCH' => array(417 => array('participant_signature' => '99504'))
    );
    \ExternalModules\ExternalModules::$username = 'data-entry-user';
    $originMismatchModule->redcap_save_record(123, 'ORIGIN-MISMATCH', 'consent', 417, null, null, null, 1);
    moduleAssert(count(payloadsForMessage($originMismatchModule, 'sigwm_bind')) === 0, 'A first binding with mismatched origins was accepted.');
    moduleAssert($originMismatchModule->logs[1][0] === 'sigwm_error_origin_mismatch', 'Origin mismatch did not append the dedicated error event.');
    moduleAssert($originMismatchModule->logs[1][1]['capture_origin'] === 'survey', 'Origin mismatch log lost the capture origin.');
    moduleAssert($originMismatchModule->logs[1][1]['save_origin'] === 'data_entry', 'Origin mismatch log lost the save origin.');

    \ExternalModules\ExternalModules::$username = 'data-entry-user';
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
    moduleAssert($uploadProvenance['capture_origin'] === 'data_entry', 'Upload provenance did not retain the data-entry origin.');
    moduleAssert($uploadProvenance['capture_username'] === 'data-entry-user', 'Upload provenance did not retain the current username.');

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
    moduleAssert($storedBinding['capture_origin'] === 'data_entry' && $storedBinding['save_origin'] === 'data_entry', 'Classic binding did not retain its origin audit fields.');
    moduleAssert($storedBinding['capture_username'] === 'data-entry-user' && $storedBinding['save_username'] === 'data-entry-user', 'Classic binding did not retain its username audit fields.');
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

    $invalidOriginModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($invalidOriginModule, 'proj', new FakeProject());
    setPrivateProperty($invalidOriginModule, 'project_id', 123);
    $invalidOriginPayload = $payload;
    $invalidOriginPayload['capture_origin'] = 'api';
    $_GET = array('event_id' => '417', 'instance' => '1', 'page' => 'consent');
    $_POST = array(
        'field_name' => 'participant_signature-linknew',
        'sigwm_envelope' => $signer->sign($invalidOriginPayload),
        'myfile_base64' => base64_encode($originalPng)
    );
    ob_start();
    invokePrivate($invalidOriginModule, 'intercept_signature_upload');
    ob_end_clean();
    moduleAssert($invalidOriginModule->exitRequested, 'A signed envelope with an unsupported capture origin was accepted.');
    moduleAssert($invalidOriginModule->logs[0][0] === 'sigwm_error_invalid_envelope', 'Invalid capture origin did not produce an envelope error.');

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
