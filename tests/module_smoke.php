<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Tests {
    class ExternalModulesStub
    {
        public static $username = null;
        public static $noAuth = false;

        public static function getUsername()
        {
            return self::$username;
        }

        public static function isNoAuth()
        {
            return self::$noAuth;
        }
    }

    class AbstractExternalModuleStub
    {
        public $framework;
        public $logs = array();
        public $exitRequested = false;
        public $testUser;
        public $projectSettings = array();
        public $failUploadProvenanceLog = false;

        public function getProjectSetting($key, $projectId = null)
        {
            return $this->projectSettings[$key] ?? false;
        }

        public function escape($value)
        {
            return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
        }

        public function log($message, $parameters = array())
        {
            if ($message === 'sigwm_upload' && $this->failUploadProvenanceLog) {
                throw new \RuntimeException('Simulated upload provenance log failure.');
            }
            $this->logs[] = array($message, $parameters);
            return count($this->logs);
        }

        public function query($sql, $parameters = array())
        {
            if (strpos($sql, 'GET_LOCK') !== false || strpos($sql, 'RELEASE_LOCK') !== false) {
                return new FakeModuleResult(array(1));
            }
            throw new \RuntimeException('Unexpected module query in smoke test.');
        }

        public function queryLogs($sql, $parameters = array())
        {
            if (strpos($sql, 'envelope_nonce_hash = ?') !== false) {
                list($message, $nonceHash) = $parameters;
                foreach ($this->logs as $index => $log) {
                    if ($log[0] === $message
                        && hash_equals((string) ($log[1]['envelope_nonce_hash'] ?? ''), (string) $nonceHash)) {
                        return new FakeModuleResult(array('log_id' => $index + 1));
                    }
                }
                return new FakeModuleResult(null);
            }

            if (strpos($sql, 'where message = ? and record = ?') !== false) {
                list($message, $record) = $parameters;
                foreach ($this->logs as $index => $log) {
                    if ($log[0] === $message && (string) ($log[1]['record'] ?? '') === (string) $record) {
                        return new FakeModuleResult(array(
                            'log_id' => $index + 1,
                            'record' => $log[1]['record']
                        ));
                    }
                }
                return new FakeModuleResult(null);
            }

            list($message, $edocId) = $parameters;
            foreach ($this->logs as $index => $log) {
                if ($log[0] === $message && (int) ($log[1]['edoc_id'] ?? 0) === (int) $edocId) {
                    return new FakeModuleResult(array(
                        'log_id' => $index + 1,
                        'payload_json' => $log[1]['payload_json'],
                        'project_id' => 123
                    ));
                }
            }
            return new FakeModuleResult(null);
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

    class Files
    {
        public static $info = array();
        public static $attributes = array();
        public static $nextEdocId = 99600;

        public static function getEdocInfo($edocId, $projectId, $includeDeleted)
        {
            if (!isset(self::$info[$edocId])
                || (int) (self::$info[$edocId]['project_id'] ?? 0) !== (int) $projectId) {
                return null;
            }
            return self::$info[$edocId];
        }

        public static function getEdocContentsAttributes($edocId)
        {
            return self::$attributes[$edocId] ?? false;
        }

        public static function uploadFile($file, $projectId)
        {
            $contents = isset($file['tmp_name']) ? @file_get_contents($file['tmp_name']) : false;
            if (!is_string($contents) || $contents === '') {
                return 0;
            }
            $edocId = self::$nextEdocId++;
            self::$info[$edocId] = array(
                'project_id' => (int) $projectId,
                'mime_type' => 'image/png',
                'doc_name' => $file['name'] ?? 'upload.png',
                'doc_size' => strlen($contents)
            );
            self::$attributes[$edocId] = array('image/png', self::$info[$edocId]['doc_name'], $contents);
            return $edocId;
        }
    }

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
                throw new \RuntimeException('Unsupported test right.');
            }
            if (!is_numeric($value) || $value === '') {
                return true;
            }
            $value = (int) $value;
            return $value < 128 ? $value === 0 : $value === 128;
        }
    }

    class FakeFramework
    {
        public $module;

        public function getUrl($file)
        {
            return '/modules/watermarked_signatures/' . $file;
        }

        public function tt($key)
        {
            $translations = array(
                'ui_upload_watermark_failed' => 'The signature could not be securely watermarked. Refresh the form or survey page, then capture the signature again.'
            );
            return $translations[$key] ?? $key;
        }

        public function setProjectSetting($key, $value, $projectId = null)
        {
            if ($this->module !== null) {
                $this->module->projectSettings[$key] = $value;
            }
        }

        public function removeProjectSetting($key, $projectId = null)
        {
            if ($this->module !== null) {
                unset($this->module->projectSettings[$key]);
            }
        }
    }

    class FakeUser
    {
        private $superUser;
        private $rights;
        private $designRights;

        public function __construct($superUser, $rights, $designRights = false)
        {
            $this->superUser = $superUser;
            $this->rights = $rights;
            $this->designRights = $designRights;
        }

        public function isSuperUser()
        {
            return $this->superUser;
        }

        public function getRights($projectId)
        {
            return $this->rights;
        }

        public function hasDesignRights($projectId)
        {
            return $this->superUser || $this->designRights;
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

    // The module invokes these REDCap and EM Framework classes by their global names.
    class_alias(__NAMESPACE__ . '\\ExternalModulesStub', 'ExternalModules\\ExternalModules');
    class_alias(__NAMESPACE__ . '\\AbstractExternalModuleStub', 'ExternalModules\\AbstractExternalModule');
    class_alias(__NAMESPACE__ . '\\Design', 'Design');
    class_alias(__NAMESPACE__ . '\\REDCap', 'REDCap');
    class_alias(__NAMESPACE__ . '\\Files', 'Files');
    class_alias(__NAMESPACE__ . '\\UserRights', 'UserRights');

    require_once __DIR__ . '/../WatermarkedSignaturesExternalModule.php';

    use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\Anchor;
    use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\EnvelopeSigner;
    use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\KeyDerivation;
    use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
    use DE\RUB\WatermarkedSignaturesExternalModule\Watermark\Renderer;
    use DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule;
    use ReflectionMethod;
    use ReflectionProperty;
    use RuntimeException;

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
            'project_reference' => null,
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
            if ($log[0] === $message && isset($log[1]['payload_json'])) {
                $payloads[] = json_decode($log[1]['payload_json'], true);
            }
        }
        return $payloads;
    }

    function countLogsForMessage($module, $message)
    {
        $count = 0;
        foreach ($module->logs as $log) {
            if ($log[0] === $message) {
                $count++;
            }
        }
        return $count;
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

    $module = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($module, 'proj', new FakeProject());
    setPrivateProperty($module, 'project_id', 123);

    moduleAssert(invokePrivate($module, 'background_image_mode') === 'redcap', 'Unset background image mode did not use the REDCap-logo default.');
    $module->projectSettings['background-image-mode'] = 'none';
    moduleAssert(invokePrivate($module, 'background_image_mode') === 'none', 'The no-background mode was not accepted.');
    $module->projectSettings['background-image-mode'] = 'invalid';
    moduleAssert(invokePrivate($module, 'background_image_mode') === 'redcap', 'Invalid background image mode did not use the REDCap-logo default.');
    $module->projectSettings = array();

    $backgroundSource = imagecreatetruecolor(64, 24);
    $backgroundWhite = imagecolorallocate($backgroundSource, 255, 255, 255);
    $backgroundBlue = imagecolorallocate($backgroundSource, 20, 80, 190);
    imagefilledrectangle($backgroundSource, 0, 0, 63, 23, $backgroundWhite);
    imagestring($backgroundSource, 2, 4, 5, 'TEST', $backgroundBlue);
    ob_start();
    imagepng($backgroundSource);
    $customBackgroundPng = ob_get_clean();
    Files::$info[99590] = array('project_id' => 123, 'mime_type' => 'image/png', 'doc_name' => 'watermark.png', 'doc_size' => strlen($customBackgroundPng));
    Files::$attributes[99590] = array('image/png', 'watermark.png', $customBackgroundPng);

    $customBackgroundModule = new WatermarkedSignaturesExternalModule();
    $customBackgroundModule->framework = new FakeFramework();
    $customBackgroundModule->projectSettings = array(
        'background-image-mode' => 'custom',
        'custom-background-image' => '99590'
    );
    setPrivateProperty($customBackgroundModule, 'proj', new FakeProject());
    setPrivateProperty($customBackgroundModule, 'project_id', 123);
    $customBackgroundProfile = invokePrivate($customBackgroundModule, 'background_image_profile');
    moduleAssert($customBackgroundProfile['mode'] === 'custom', 'Configured custom background image was not selected.');
    moduleAssert($customBackgroundProfile['requested_mode'] === 'custom', 'Configured custom background image lost its selected mode.');
    moduleAssert($customBackgroundProfile['sha256'] === hash('sha256', $customBackgroundPng), 'Custom background image digest was not calculated.');
    moduleAssert($customBackgroundProfile['contents'] === $customBackgroundPng, 'Custom background image contents were not read from REDCap storage.');
    ob_start();
    invokePrivate($customBackgroundModule, 'inject_capture_envelopes', array('consent', 417, 'data_entry'));
    $customBackgroundConfig = injectedConfig(ob_get_clean());
    $customBackgroundUpload = captureSignatureUpload(
        $customBackgroundModule,
        $customBackgroundConfig['envelopes']['participant_signature'],
        $originalPng,
        99591
    );
    moduleAssert($customBackgroundUpload['background_image_mode'] === 'custom', 'Upload provenance did not retain the selected custom background image mode.');
    moduleAssert($customBackgroundUpload['background_image_effective_mode'] === 'custom', 'Upload provenance did not retain the applied custom background image mode.');
    moduleAssert($customBackgroundUpload['background_image_sha256'] === hash('sha256', $customBackgroundPng), 'Upload provenance did not retain the custom background image digest.');
    moduleAssert($customBackgroundUpload['background_image_rotation'] === Renderer::DEFAULT_BACKGROUND_IMAGE_ROTATION, 'Upload provenance did not retain the default custom background image rotation.');

    Files::$info[99592] = array('project_id' => 123, 'mime_type' => 'image/png', 'doc_name' => 'invalid.png');
    Files::$attributes[99592] = array('image/png', 'invalid.png', 'not a PNG');
    $invalidBackgroundModule = new WatermarkedSignaturesExternalModule();
    $invalidBackgroundModule->projectSettings = array(
        'background-image-mode' => 'custom',
        'custom-background-image' => '99592'
    );
    setPrivateProperty($invalidBackgroundModule, 'proj', new FakeProject());
    setPrivateProperty($invalidBackgroundModule, 'project_id', 123);
    $invalidBackgroundProfile = invokePrivate($invalidBackgroundModule, 'background_image_profile');
    moduleAssert($invalidBackgroundProfile['requested_mode'] === 'custom' && $invalidBackgroundProfile['mode'] === 'redcap', 'Invalid custom background image did not fall back to the REDCap logo.');
    moduleAssert($invalidBackgroundProfile['sha256'] === null, 'Invalid custom background image retained a digest.');
    moduleAssert($invalidBackgroundModule->logs[0][0] === 'sigwm_error_background_image', 'Invalid custom background image did not create a diagnostic event.');

    $projectSettingsModule = new WatermarkedSignaturesExternalModule();
    $projectSettingsFramework = new FakeFramework();
    $projectSettingsFramework->module = $projectSettingsModule;
    $projectSettingsModule->framework = $projectSettingsFramework;
    $projectSettingsModule->testUser = new FakeUser(false, array(), true);
    setPrivateProperty($projectSettingsModule, 'proj', new FakeProject());
    setPrivateProperty($projectSettingsModule, 'project_id', 123);
    $initialSettings = $projectSettingsModule->get_project_settings_state(123);
    moduleAssert($initialSettings['retention_days'] === 90 && $initialSettings['background_image_mode'] === 'redcap', 'Custom project settings did not expose the expected defaults.');
    moduleAssert($initialSettings['background_image_rotation'] === Renderer::DEFAULT_BACKGROUND_IMAGE_ROTATION, 'Custom project settings did not preserve the default custom-image rotation.');

    $largeBackground = imagecreatetruecolor(1024, 512);
    $largeBackgroundWhite = imagecolorallocate($largeBackground, 255, 255, 255);
    $largeBackgroundBlue = imagecolorallocate($largeBackground, 30, 95, 190);
    imagefilledrectangle($largeBackground, 0, 0, 1023, 511, $largeBackgroundWhite);
    imagestring($largeBackground, 5, 200, 240, 'NORMALIZED', $largeBackgroundBlue);
    ob_start();
    imagepng($largeBackground);
    $largeBackgroundPng = ob_get_clean();
    $temporaryUpload = tempnam(sys_get_temp_dir(), 'sigwm-test-');
    moduleAssert($temporaryUpload !== false && file_put_contents($temporaryUpload, $largeBackgroundPng) === strlen($largeBackgroundPng), 'Could not prepare a custom background image upload.');
    try {
        $savedSettings = $projectSettingsModule->save_project_settings(123, array(
            'retention_days' => '17',
            'public_project_reference' => 'SIGWM-TEST',
            'background_image_mode' => 'custom',
            'background_image_rotation' => '-30'
        ), array(
            'error' => UPLOAD_ERR_OK,
            'name' => 'department-seal.png',
            'size' => strlen($largeBackgroundPng),
            'tmp_name' => $temporaryUpload
        ));
    } finally {
        if (is_file($temporaryUpload)) {
            unlink($temporaryUpload);
        }
    }
    moduleAssert($savedSettings['ok'], 'Custom project settings could not save a normalized custom image.');
    moduleAssert($projectSettingsModule->projectSettings['unbound-upload-retention-days'] === '17', 'Custom project settings did not persist retention.');
    moduleAssert($projectSettingsModule->projectSettings['public-project-reference'] === 'SIGWM-TEST', 'Custom project settings did not persist the public project reference.');
    moduleAssert($projectSettingsModule->projectSettings['background-image-mode'] === 'custom', 'Custom project settings did not persist the selected background mode.');
    moduleAssert($projectSettingsModule->projectSettings['background-image-rotation'] === '-30', 'Custom project settings did not persist the custom-image rotation.');
    $savedCustomImage = $savedSettings['state']['custom_image'];
    moduleAssert($savedCustomImage['available'] && $savedCustomImage['width'] === 512 && $savedCustomImage['height'] === 256, 'Custom project settings did not normalize the stored image to the 512px limit.');
    moduleAssert($savedCustomImage['doc_name'] === 'department-seal.png', 'Custom project settings did not preserve the original custom-image filename.');
    moduleAssert(strpos($savedCustomImage['preview_data_url'], 'data:image/png;base64,') === 0, 'Custom project settings did not provide a safe preview data URL.');
    $savedImageBytes = Files::$attributes[(int) $savedCustomImage['edoc_id']][2];
    moduleAssert(strlen($savedImageBytes) <= Renderer::MAX_CUSTOM_BACKGROUND_IMAGE_BYTES, 'Custom project settings stored an image above the final size limit.');
    $savedBackgroundProfile = invokePrivate($projectSettingsModule, 'background_image_profile');
    moduleAssert($savedBackgroundProfile['mode'] === 'custom' && $savedBackgroundProfile['rotation'] === -30, 'Custom project settings did not apply the saved image rotation to rendering.');
    $ajaxSettingsValidation = $projectSettingsModule->redcap_module_ajax(
        WatermarkedSignaturesExternalModule::AJAX_VALIDATE_PROJECT_SETTINGS,
        array(
            'retention_days' => '17',
            'public_project_reference' => 'INVALID!REFERENCE',
            'background_image_mode' => 'custom',
            'background_image_rotation' => '181',
            'has_pending_custom_image' => false
        ),
        123,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null
    );
    moduleAssert(!$ajaxSettingsValidation['ok'], 'Project settings AJAX validation accepted invalid values.');
    moduleAssert($ajaxSettingsValidation['errors']['public_project_reference'] === 'settings_error_public_project_reference', 'Project settings AJAX validation did not identify an invalid public reference.');
    moduleAssert($ajaxSettingsValidation['errors']['background_image_rotation'] === 'settings_error_background_rotation', 'Project settings AJAX validation did not identify an invalid rotation.');
    $maximumProjectReferenceValidation = $projectSettingsModule->validate_project_settings_input(123, array(
        'retention_days' => '17',
        'public_project_reference' => str_repeat('P', Renderer::MAX_PROJECT_REFERENCE_LENGTH),
        'background_image_mode' => 'redcap',
        'background_image_rotation' => '-30'
    ));
    moduleAssert($maximumProjectReferenceValidation['ok'], 'Project settings rejected a 20-character public project reference.');
    $oversizedProjectReferenceValidation = $projectSettingsModule->validate_project_settings_input(123, array(
        'retention_days' => '17',
        'public_project_reference' => str_repeat('P', Renderer::MAX_PROJECT_REFERENCE_LENGTH + 1),
        'background_image_mode' => 'redcap',
        'background_image_rotation' => '-30'
    ));
    moduleAssert($oversizedProjectReferenceValidation['errors']['public_project_reference'] === 'settings_error_public_project_reference', 'Project settings accepted a public project reference longer than 20 characters.');
    $retainedImageEdocId = $projectSettingsModule->projectSettings['custom-background-image'];
    $redcapSettings = $projectSettingsModule->save_project_settings(123, array(
        'retention_days' => '17',
        'public_project_reference' => 'SIGWM-TEST',
        'background_image_mode' => 'redcap',
        'background_image_rotation' => '-30'
    ), null);
    moduleAssert($redcapSettings['ok'], 'Project settings could not switch back to the REDCap logo.');
    moduleAssert($projectSettingsModule->projectSettings['custom-background-image'] === $retainedImageEdocId, 'Custom image was not retained while the REDCap-logo mode was selected.');
    moduleAssert($redcapSettings['state']['custom_image']['available'], 'Retained custom image became unavailable after selecting the REDCap logo.');
    $replacementUpload = tempnam(sys_get_temp_dir(), 'sigwm-test-');
    moduleAssert($replacementUpload !== false && file_put_contents($replacementUpload, $largeBackgroundPng) === strlen($largeBackgroundPng), 'Could not prepare a conflicting custom-image replacement upload.');
    $edocIdBeforeRemoval = Files::$nextEdocId;
    try {
        $removedImageSettings = $projectSettingsModule->save_project_settings(123, array(
            'retention_days' => '17',
            'public_project_reference' => 'SIGWM-TEST',
            'background_image_mode' => 'redcap',
            'background_image_rotation' => '-30',
            'remove_custom_background_image' => '1'
        ), array(
            'error' => UPLOAD_ERR_OK,
            'name' => 'replacement.png',
            'size' => strlen($largeBackgroundPng),
            'tmp_name' => $replacementUpload
        ));
    } finally {
        if (is_file($replacementUpload)) {
            unlink($replacementUpload);
        }
    }
    moduleAssert($removedImageSettings['ok'], 'Custom project settings could not remove the stored custom image.');
    moduleAssert(!isset($projectSettingsModule->projectSettings['custom-background-image']), 'Removing the custom image did not clear its project setting.');
    moduleAssert(!$removedImageSettings['state']['custom_image']['available'], 'Removed custom image remained available to the module.');
    moduleAssert(Files::$nextEdocId === $edocIdBeforeRemoval, 'An explicitly removed custom image was unexpectedly replaced.');
    $missingCustomImage = $projectSettingsModule->save_project_settings(123, array(
        'retention_days' => '17',
        'public_project_reference' => 'SIGWM-TEST',
        'background_image_mode' => 'custom',
        'background_image_rotation' => '999'
    ), null);
    moduleAssert(!$missingCustomImage['ok'] && $missingCustomImage['error_key'] === 'settings_error_background_rotation', 'Custom project settings accepted an invalid rotation.');

    moduleAssert(invokePrivate($module, 'unbound_upload_retention_days', array(123)) === 90, 'Unset retention setting did not use the 90-day default.');
    $module->projectSettings['unbound-upload-retention-days'] = '0';
    moduleAssert(invokePrivate($module, 'unbound_upload_retention_days', array(123)) === 0, 'Retention setting did not support disabling automatic purge.');
    $module->projectSettings['unbound-upload-retention-days'] = 'invalid';
    moduleAssert(invokePrivate($module, 'unbound_upload_retention_days', array(123)) === 90, 'Invalid retention setting did not fall back to the default.');
    $module->projectSettings['unbound-upload-retention-days'] = '99999';
    moduleAssert(invokePrivate($module, 'unbound_upload_retention_days', array(123)) === 3650, 'Retention setting did not enforce its maximum.');
    $module->projectSettings = array();

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
        'project_reference' => 'SIGWM-TEST',
        'issued_at' => $now,
        'expires_at' => $now + 3600,
        'nonce' => ReferenceGenerator::nonce(),
        'purpose' => 'signature'
    );
    $signer = new EnvelopeSigner(KeyDerivation::derive(KeyDerivation::ENVELOPE_INFO));

    $multiEnvelopeModule = new WatermarkedSignaturesExternalModule();
    $multiEnvelopeModule->framework = new FakeFramework();
    $multiEnvelopeModule->projectSettings['public-project-reference'] = 'SIGWM-TEST';
    $multiEnvelopeProject = new FakeProject(null, true);
    $multiEnvelopeProject->metadata['participant_signature']['misc'] = '@WATERMARKED-SIGNATURE="CONSENT"';
    $multiEnvelopeProject->metadata['witness_signature']['misc'] = '@WATERMARKED-SIGNATURE="WITNESS"';
    setPrivateProperty($multiEnvelopeModule, 'proj', $multiEnvelopeProject);
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
    moduleAssert($participantEnvelope['project_reference'] === 'SIGWM-TEST' && $witnessEnvelope['project_reference'] === 'SIGWM-TEST', 'Configured public project reference was not signed into every field envelope.');
    moduleAssert($participantEnvelope['field_reference'] === 'CONSENT' && $witnessEnvelope['field_reference'] === 'WITNESS', 'Field references were not signed into their respective envelopes.');

    $fieldReferenceUpload = captureSignatureUpload(
        $multiEnvelopeModule,
        $multiEnvelopeConfig['envelopes']['participant_signature'],
        $originalPng,
        99507
    );
    moduleAssert($fieldReferenceUpload['field_reference'] === 'CONSENT', 'Upload provenance did not retain the signed field reference.');
    REDCap::$data = array(
        'FIELD-REFERENCE' => array(417 => array('participant_signature' => '99507'))
    );
    $multiEnvelopeModule->redcap_save_record(123, 'FIELD-REFERENCE', 'consent', 417, null, null, null, 1);
    $fieldReferenceBinding = payloadsForMessage($multiEnvelopeModule, 'sigwm_bind')[0];
    moduleAssert($fieldReferenceBinding['field_reference'] === 'CONSENT', 'Binding did not retain the authenticated field reference.');

    $invalidFieldReferenceProject = new FakeProject();
    $invalidFieldReferenceProject->metadata['participant_signature']['misc'] = '@WATERMARKED-SIGNATURE="ENHANCED-MIGHTILY"';
    $invalidFieldReferenceModule = new WatermarkedSignaturesExternalModule();
    $invalidFieldReferenceModule->framework = new FakeFramework();
    setPrivateProperty($invalidFieldReferenceModule, 'proj', $invalidFieldReferenceProject);
    setPrivateProperty($invalidFieldReferenceModule, 'project_id', 123);
    ob_start();
    invokePrivate($invalidFieldReferenceModule, 'inject_capture_envelopes', array('consent', 417, 'data_entry'));
    $invalidFieldReferenceConfig = injectedConfig(ob_get_clean());
    $invalidFieldReferenceEnvelope = $signer->verify($invalidFieldReferenceConfig['envelopes']['participant_signature']);
    moduleAssert($invalidFieldReferenceEnvelope['field_reference'] === null, 'An invalid field-reference action-tag parameter was not omitted.');
    moduleAssert($invalidFieldReferenceEnvelope['field_reference_error'] === 'field_reference_too_long', 'An oversized field-reference action-tag parameter was not identified.');
    moduleAssert($invalidFieldReferenceEnvelope['field_reference_error_value'] === 'ENHANCED-MIGHTILY' && $invalidFieldReferenceEnvelope['field_reference_error_length'] === 17, 'An oversized field-reference action-tag parameter did not retain its diagnostic value and length.');
    $invalidFieldReferenceUpload = captureSignatureUpload(
        $invalidFieldReferenceModule,
        $invalidFieldReferenceConfig['envelopes']['participant_signature'],
        $originalPng,
        99508
    );
    moduleAssert($invalidFieldReferenceUpload['field_reference'] === null, 'An invalid field-reference action-tag parameter reached upload provenance.');
    moduleAssert(countLogsForMessage($invalidFieldReferenceModule, 'sigwm_error_field_reference') === 1, 'An invalid field-reference action-tag parameter was not logged during capture.');
    foreach ($invalidFieldReferenceModule->logs as $log) {
        if ($log[0] !== 'sigwm_error_field_reference') {
            continue;
        }
        moduleAssert($log[1]['field_reference_error'] === 'field_reference_too_long', 'The field-reference diagnostic did not record the precise error code.');
        moduleAssert($log[1]['field_reference_value'] === 'ENHANCED-MIGHTILY' && $log[1]['field_reference_length'] === 17 && $log[1]['field_reference_maximum_length'] === 16, 'The field-reference diagnostic did not record the configured value, length, and limit.');
        break;
    }

    $duplicateConfiguration = invokePrivate($invalidFieldReferenceModule, 'signature_field_configuration', array(array(
        'element_type' => 'file',
        'element_validation_type' => 'signature',
        'misc' => '@WATERMARKED-SIGNATURE @WATERMARKED-SIGNATURE="CONSENT"'
    )));
    moduleAssert($duplicateConfiguration['configured'] && $duplicateConfiguration['field_reference'] === null && $duplicateConfiguration['field_reference_error'] === 'multiple_action_tags', 'Duplicate watermark action tags were not rejected as a field-reference configuration error.');

    $maximumFieldConfiguration = invokePrivate($invalidFieldReferenceModule, 'signature_field_configuration', array(array(
        'element_type' => 'file',
        'element_validation_type' => 'signature',
        'misc' => '@WATERMARKED-SIGNATURE="' . str_repeat('F', Renderer::MAX_FIELD_REFERENCE_LENGTH) . '"'
    )));
    moduleAssert($maximumFieldConfiguration['field_reference'] === str_repeat('F', Renderer::MAX_FIELD_REFERENCE_LENGTH), 'A 16-character field reference was rejected.');

    $invalidFieldReferenceProject->metadata['ordinary_upload'] = array(
        'form_name' => 'consent',
        'element_type' => 'file',
        'element_validation_type' => '',
        'misc' => '@WATERMARKED-SIGNATURE="NOT-APPLIED"'
    );
    $actionTagAudit = $invalidFieldReferenceModule->get_project_action_tag_audit(123);
    moduleAssert(count($actionTagAudit) === 2, 'The project action-tag audit did not report every invalid tag.');
    moduleAssert($actionTagAudit[0]['field'] === 'participant_signature' && $actionTagAudit[0]['code'] === 'field_reference_too_long' && $actionTagAudit[0]['reference_length'] === 17 && $actionTagAudit[0]['maximum_length'] === 16, 'The action-tag audit did not report the oversized field reference precisely.');
    moduleAssert($actionTagAudit[1]['field'] === 'ordinary_upload' && $actionTagAudit[1]['code'] === 'action_tag_unsupported_field', 'The action-tag audit did not report a tag on an unsupported field.');

    $verificationLink = array('key' => 'signature-verification', 'url' => 'pages/verify-signature.php');
    $projectSettingsLink = array('key' => 'project-settings', 'url' => 'pages/project-settings.php');
    $linkModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($linkModule, 'proj', new FakeProject());
    setPrivateProperty($linkModule, 'project_id', 123);
    $linkModule->testUser = new FakeUser(false, array(
        'data_entry' => '[consent,129]',
        'group_id' => ''
    ));
    moduleAssert($linkModule->redcap_module_link_check_display(123, $verificationLink) === $verificationLink, 'Read-only form user did not receive the verification link.');
    moduleAssert($linkModule->redcap_module_link_check_display(123, $projectSettingsLink) === null, 'User without design rights received the project settings link.');
    $linkModule->testUser = new FakeUser(false, array(
        'data_entry' => '[consent,128]',
        'group_id' => ''
    ));
    moduleAssert($linkModule->redcap_module_link_check_display(123, $verificationLink) === null, 'User without signature-form access received the verification link.');
    $linkModule->testUser = new FakeUser(false, array(
        'data_entry' => '[consent,128]',
        'group_id' => ''
    ), true);
    moduleAssert($linkModule->redcap_module_link_check_display(123, $projectSettingsLink) === $projectSettingsLink, 'Project designer did not receive the project settings link.');
    $administratorVerificationLink = array('key' => 'administrator-signature-verification', 'url' => 'pages/admin-verify-signature.php');
    moduleAssert($linkModule->redcap_module_link_check_display(null, $administratorVerificationLink) === null, 'Non-administrator received the global verification link.');
    $administratorFactoryDenied = false;
    try {
        $linkModule->get_administrator_verification_controller();
    } catch (\RuntimeException $exception) {
        $administratorFactoryDenied = true;
    }
    moduleAssert($administratorFactoryDenied, 'Non-administrator reached the global verification controller factory.');
    $linkModule->testUser = new FakeUser(true, array());
    moduleAssert($linkModule->redcap_module_link_check_display(null, $administratorVerificationLink) === $administratorVerificationLink, 'Administrator did not receive the global verification link.');
    moduleAssert(
        $linkModule->get_administrator_verification_controller() instanceof \DE\RUB\WatermarkedSignaturesExternalModule\Verification\AdministratorVerificationController,
        'Administrator could not create the global verification controller.'
    );

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
    moduleAssert($autoNumberEnvelope['project_reference'] === null, 'Unset public project reference was not represented explicitly as null.');
    moduleAssert(!array_key_exists('record_id', $autoNumberEnvelope), 'Capture envelope contained a pre-save record ID.');
    $autoNumberUpload = captureSignatureUpload(
        $autoNumberModule,
        $autoNumberConfig['envelopes']['participant_signature'],
        $originalPng,
        99501
    );
    moduleAssert($autoNumberUpload['capture_origin'] === 'data_entry', 'Data-entry upload provenance lost its capture origin.');
    moduleAssert($autoNumberUpload['capture_username'] === 'auto-capture-user', 'Upload provenance did not snapshot the authenticated capture username.');
    moduleAssert($autoNumberUpload['project_reference'] === null, 'Upload provenance did not retain the public project reference snapshot.');
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
    moduleAssert($autoNumberBinding['project_reference'] === null, 'Binding did not retain the public project reference snapshot.');
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

    $replaySurveyModule = new WatermarkedSignaturesExternalModule();
    $replaySurveyModule->framework = new FakeFramework();
    setPrivateProperty($replaySurveyModule, 'proj', new FakeProject());
    setPrivateProperty($replaySurveyModule, 'project_id', 123);
    \ExternalModules\ExternalModules::$username = null;
    ExternalModulesStub::$noAuth = true;
    ob_start();
    $replaySurveyModule->redcap_survey_page(123, null, 'consent', 417, null, 'public-survey-hash', null, 1);
    $replaySurveyConfig = injectedConfig(ob_get_clean());
    $replayEnvelope = $replaySurveyConfig['envelopes']['participant_signature'];
    captureSignatureUpload($replaySurveyModule, $replayEnvelope, $originalPng, 99505);
    $replayLogCount = count($replaySurveyModule->logs);
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_GET = array('NOAUTH' => '1', 'event_id' => '417', 'instance' => '1', 'page' => 'consent');
    $_POST = array(
        'field_name' => 'participant_signature-linknew',
        'sigwm_envelope' => $replayEnvelope,
        'myfile_base64' => base64_encode($originalPng)
    );
    ob_start();
    invokePrivate($replaySurveyModule, 'intercept_signature_upload');
    $replayFailureResponse = ob_get_clean();
    ExternalModulesStub::$noAuth = false;

    moduleAssert($replaySurveyModule->exitRequested, 'Replayed no-auth envelope did not fail closed.');
    moduleAssert(count($replaySurveyModule->logs) === $replayLogCount, 'Replayed no-auth envelope appended a log entry.');
    moduleAssert(count(payloadsForMessage($replaySurveyModule, 'sigwm_upload')) === 1, 'Replayed no-auth envelope created another upload provenance event.');
    moduleAssert(strpos($replayFailureResponse, 'could not be securely watermarked') !== false, 'Replayed no-auth envelope did not return the standard failure response.');

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
    moduleAssert(
        $info[0] === 460 && $info[1] === 120 + Renderer::FOOTER_HEIGHT,
        'Upload interceptor did not replace the PNG with the two-line public-reference footer.'
    );
    moduleAssert(count($module->logs) === 1 && $module->logs[0][0] === 'sigwm_upload', 'Upload provenance was not logged.');
    moduleAssert($module->logs[0][1]['edoc_id'] === 98137, 'The returned edoc ID was not captured.');
    moduleAssert(strpos($response, "stopUpload(1,'participant_signature','98137'") !== false, 'The iframe response was altered.');
    $uploadProvenance = json_decode($module->logs[0][1]['payload_json'], true);
    moduleAssert($uploadProvenance['file_sha256'] === hash('sha256', $watermarkedPng), 'Provenance digest does not cover the final PNG.');
    moduleAssert($uploadProvenance['watermark_version'] === 1, 'Provenance did not retain the WM1 format version.');
    moduleAssert((bool) preg_match('/Z$/', $uploadProvenance['captured_at']), 'Provenance timestamp is not UTC.');
    moduleAssert($uploadProvenance['capture_origin'] === 'data_entry', 'Upload provenance did not retain the data-entry origin.');
    moduleAssert($uploadProvenance['capture_username'] === 'data-entry-user', 'Upload provenance did not retain the current username.');
    moduleAssert($uploadProvenance['project_reference'] === 'SIGWM-TEST', 'Upload provenance did not retain the public project reference snapshot.');
    moduleAssert($uploadProvenance['field_reference'] === null, 'A legacy envelope without a field reference did not remain valid.');

    $responseFailureModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($responseFailureModule, 'proj', new FakeProject());
    setPrivateProperty($responseFailureModule, 'project_id', 123);
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_GET = array('event_id' => '417', 'instance' => '1', 'page' => 'consent');
    $_POST = array(
        'field_name' => 'participant_signature-linknew',
        'sigwm_envelope' => $signer->sign($payload),
        'myfile_base64' => base64_encode($originalPng)
    );
    ob_start();
    ob_start();
    invokePrivate($responseFailureModule, 'intercept_signature_upload');
    echo ob_get_clean();
    // A success response with an altered edoc-ID shape must leave a durable
    // diagnostic instead of silently losing this capture's provenance.
    echo '<script>window.parent.window.stopUpload(1,"participant_signature",98138,"signature.png","",417,"","","",1,true);</script>';
    ob_end_flush();
    ob_end_flush();
    ob_get_clean();
    moduleAssert(count($responseFailureModule->logs) === 1, 'An unparseable successful upload response did not produce a diagnostic log entry.');
    moduleAssert($responseFailureModule->logs[0][0] === 'sigwm_error_upload_provenance_response', 'An unparseable successful upload response used the wrong diagnostic event.');
    moduleAssert($responseFailureModule->logs[0][1]['capture_ref'] !== '', 'The response-parse diagnostic did not retain the capture reference.');
    moduleAssert($responseFailureModule->logs[0][1]['edoc_id'] === '', 'The response-parse diagnostic incorrectly claimed an edoc ID.');

    $loggingFailureModule = new WatermarkedSignaturesExternalModule();
    $loggingFailureModule->failUploadProvenanceLog = true;
    setPrivateProperty($loggingFailureModule, 'proj', new FakeProject());
    setPrivateProperty($loggingFailureModule, 'project_id', 123);
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_GET = array('event_id' => '417', 'instance' => '1', 'page' => 'consent');
    $_POST = array(
        'field_name' => 'participant_signature-linknew',
        'sigwm_envelope' => $signer->sign($payload),
        'myfile_base64' => base64_encode($originalPng)
    );
    ob_start();
    ob_start();
    invokePrivate($loggingFailureModule, 'intercept_signature_upload');
    echo ob_get_clean();
    echo "<script>window.parent.window.stopUpload(1,'participant_signature','98139','signature.png','',417,'','','',1,true);</script>";
    ob_end_flush();
    ob_end_flush();
    ob_get_clean();
    moduleAssert(count($loggingFailureModule->logs) === 1, 'A failed provenance write did not produce a durable diagnostic log entry.');
    moduleAssert($loggingFailureModule->logs[0][0] === 'sigwm_error_upload_provenance_logging', 'A failed provenance write used the wrong diagnostic event.');
    moduleAssert($loggingFailureModule->logs[0][1]['edoc_id'] === 98139, 'The provenance-write diagnostic did not retain the edoc ID.');
    moduleAssert(strpos($loggingFailureModule->logs[0][1]['technical_message'], 'could not be logged') !== false, 'The provenance-write diagnostic was not actionable.');

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
    moduleAssert($storedBinding['project_reference'] === 'SIGWM-TEST', 'Binding did not retain the public project reference snapshot.');
    moduleAssert(isset($storedBinding['binding_mac']), 'Binding MAC was not stored.');

    $module->redcap_save_record(123, 'R-001', 'consent', 417, null, null, null, 1);
    moduleAssert(count($module->logs) === 2, 'Repeated save appended a duplicate binding.');

    $formRenameModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($formRenameModule, 'proj', new FakeProject());
    setPrivateProperty($formRenameModule, 'project_id', 123);
    $_POST = array();
    $formRenameModule->append_upload_provenance(uploadProvenance('participant_signature', 98140));
    REDCap::$data = array(
        'RENAME-OLD' => array(417 => array('participant_signature' => '98140'))
    );
    $formRenameModule->redcap_save_record(123, 'RENAME-OLD', 'consent', 417, null, null, null, 1);
    // REDCap changes the module log's indexed record column before calling
    // redcap_save_record after a form-level record-ID rename.
    $formRenameModule->logs[1][1]['record'] = 'RENAME-NEW';
    REDCap::$data = array(
        'RENAME-NEW' => array(417 => array('participant_signature' => '98140'))
    );
    $_POST = array('__old_id__' => 'RENAME-OLD');
    $formRenameModule->redcap_save_record(123, 'RENAME-NEW', 'consent', 417, null, null, null, 1);
    $formRenameEvents = payloadsForMessage($formRenameModule, 'sigwm_record_rename');
    moduleAssert(count($formRenameEvents) === 1, 'A form-save record rename was not tracked.');
    moduleAssert($formRenameEvents[0]['old_record_id'] === 'RENAME-OLD' && $formRenameEvents[0]['new_record_id'] === 'RENAME-NEW', 'Form-save record rename captured the wrong record IDs.');
    moduleAssert($formRenameEvents[0]['rename_origin'] === 'data_entry_form_save', 'Form-save record rename has the wrong origin.');
    moduleAssert($formRenameModule->logs[2][1]['record'] === 'RENAME-NEW', 'Record-rename log was not indexed by the current record ID.');

    $directRenameModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($directRenameModule, 'proj', new FakeProject());
    setPrivateProperty($directRenameModule, 'project_id', 123);
    $_POST = array();
    $directRenameModule->append_upload_provenance(uploadProvenance('participant_signature', 98141));
    REDCap::$data = array(
        'HOME-OLD' => array(417 => array('participant_signature' => '98141'))
    );
    $directRenameModule->redcap_save_record(123, 'HOME-OLD', 'consent', 417, null, null, null, 1);
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_GET = array('route' => 'DataEntryController:renameRecord');
    $_POST = array('record' => 'HOME-OLD', 'new_record' => 'HOME-NEW');
    ob_start();
    ob_start();
    invokePrivate($directRenameModule, 'capture_direct_record_rename');
    echo ob_get_clean();
    $directRenameModule->logs[1][1]['record'] = 'HOME-NEW';
    echo '1';
    ob_end_flush();
    ob_end_flush();
    ob_get_clean();
    $directRenameEvents = payloadsForMessage($directRenameModule, 'sigwm_record_rename');
    moduleAssert(count($directRenameEvents) === 1, 'A successful record-home rename was not tracked.');
    moduleAssert($directRenameEvents[0]['old_record_id'] === 'HOME-OLD' && $directRenameEvents[0]['new_record_id'] === 'HOME-NEW', 'Record-home rename captured the wrong record IDs.');
    moduleAssert($directRenameEvents[0]['rename_origin'] === 'data_entry_record_home', 'Record-home rename has the wrong origin.');

    $apiRenameModule = new WatermarkedSignaturesExternalModule();
    setPrivateProperty($apiRenameModule, 'proj', new FakeProject());
    setPrivateProperty($apiRenameModule, 'project_id', 123);
    $_POST = array();
    $apiRenameModule->append_upload_provenance(uploadProvenance('participant_signature', 98142));
    REDCap::$data = array(
        'API-OLD' => array(417 => array('participant_signature' => '98142'))
    );
    $apiRenameModule->redcap_save_record(123, 'API-OLD', 'consent', 417, null, null, null, 1);
    ob_start();
    ob_start();
    moduleAssert($apiRenameModule->redcap_module_api_before(123, array(
        'content' => 'record',
        'action' => 'rename',
        'record' => 'API-OLD',
        'new_record_name' => 'API-NEW'
    )) === null, 'API rename pre-hook unexpectedly returned an error.');
    echo ob_get_clean();
    $apiRenameModule->logs[1][1]['record'] = 'API-NEW';
    echo '1';
    ob_end_flush();
    ob_end_flush();
    ob_get_clean();
    $apiRenameEvents = payloadsForMessage($apiRenameModule, 'sigwm_record_rename');
    moduleAssert(count($apiRenameEvents) === 1, 'A successful API rename was not tracked.');
    moduleAssert($apiRenameEvents[0]['old_record_id'] === 'API-OLD' && $apiRenameEvents[0]['new_record_id'] === 'API-NEW', 'API rename captured the wrong record IDs.');
    moduleAssert($apiRenameEvents[0]['rename_origin'] === 'api', 'API rename has the wrong origin.');

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
    $invalidOriginModule->framework = new FakeFramework();
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
    $scopeMismatchModule->framework = new FakeFramework();
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
    $failedModule->framework = new FakeFramework();
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
    moduleAssert(strpos($failureResponse, 'stopUpload(0, "participant_signature"') !== false, 'The upload failure response did not emit a JSON-encoded field name.');
    moduleAssert(strpos($failureResponse, ", 3, true)") !== false, 'The failure response lost the repeat instance.');

    $noAuthFailureModule = new WatermarkedSignaturesExternalModule();
    $noAuthFailureModule->framework = new FakeFramework();
    setPrivateProperty($noAuthFailureModule, 'proj', new FakeProject());
    setPrivateProperty($noAuthFailureModule, 'project_id', 123);
    ExternalModulesStub::$noAuth = true;
    $_GET = array('NOAUTH' => '1', 'event_id' => '417', 'instance' => '3');
    $_POST = array(
        'field_name' => 'participant_signature-linknew',
        'myfile_base64' => base64_encode($originalPng)
    );

    ob_start();
    invokePrivate($noAuthFailureModule, 'intercept_signature_upload');
    $noAuthFailureResponse = ob_get_clean();
    ExternalModulesStub::$noAuth = false;

    moduleAssert($noAuthFailureModule->exitRequested, 'No-auth missing envelopes do not fail closed.');
    moduleAssert($noAuthFailureModule->logs === array(), 'No-auth upload failures were written to the durable module log.');
    moduleAssert(strpos($noAuthFailureResponse, 'could not be securely watermarked') !== false, 'The no-auth upload failure response is missing.');

    ExternalModulesStub::$noAuth = true;
    moduleAssert(
        invokePrivate($noAuthFailureModule, 'safe_log_event', array('sigwm_error_test', array('technical_message' => 'test'))) === null,
        'No-auth technical logging was not suppressed.'
    );
    ExternalModulesStub::$noAuth = false;
    moduleAssert($noAuthFailureModule->logs === array(), 'No-auth safe logging appended a durable module log entry.');

    $_POST = array('field_name' => 'participant_signature</script><script>alert(1)</script>-linknew');
    moduleAssert(invokePrivate($failedModule, 'posted_field_name') === null, 'A hostile posted field name was accepted.');

    echo "Watermarked Signatures module smoke tests passed.\n";
}
