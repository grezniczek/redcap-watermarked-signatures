<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Tests;

require_once __DIR__ . '/../classes/Crypto/Base32.php';
require_once __DIR__ . '/../classes/Crypto/Base64Url.php';
require_once __DIR__ . '/../classes/Crypto/ReferenceGenerator.php';
require_once __DIR__ . '/../classes/Verification/ProjectAccessPolicy.php';
require_once __DIR__ . '/../classes/Verification/RedcapFieldLink.php';
require_once __DIR__ . '/../classes/Verification/ProjectVerificationController.php';

use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\ProjectAccessPolicy;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\RedcapFieldLink;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\ProjectVerificationController;
use RuntimeException;

if (!defined('APP_PATH_WEBROOT')) {
    define('APP_PATH_WEBROOT', '/redcap/');
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
            throw new RuntimeException('Unsupported test right.');
        }
        if (!is_numeric($value) || $value === '') {
            return true;
        }
        $value = (int) $value;
        return $value < 128 ? $value === 0 : $value === 128;
    }
}

// ProjectAccessPolicy calls REDCap's global UserRights API.
class_alias(__NAMESPACE__ . '\\UserRights', 'UserRights');

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
            'context_ref' => 'C:1111-2222-3333-4',
            'anchor' => 'A:AAAA-BBBB-CCCC-DDDD',
            'capture_origin' => 'data_entry',
            'capture_username' => 'capture-user',
            'captured_at' => '2026-07-17T13:00:00Z',
            'edoc_id' => 98137,
            'file_sha256' => str_repeat('a', 64),
            'project_reference' => 'SIGWM-TEST',
            'background_image_mode' => 'custom',
            'background_image_effective_mode' => 'custom',
            'background_image_sha256' => str_repeat('b', 64),
            'background_image_rotation' => -30,
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
projectUiAssert($presented['details']['background_image_mode'] === 'custom', 'Authorized details did not show the selected background image mode.');
projectUiAssert($presented['details']['background_image_effective_mode'] === 'custom', 'Authorized details did not show the applied background image mode.');
projectUiAssert($presented['details']['background_image_sha256'] === str_repeat('b', 64), 'Authorized details did not show the custom background image digest.');
projectUiAssert($presented['details']['background_image_rotation'] === -30, 'Authorized details did not show the applied background image rotation.');
projectUiAssert($presented['details']['capture_ref'] === $captureReference, 'Authorized details did not retain the canonical S: capture-reference format.');
projectUiAssert($presented['details']['context_ref'] === 'C:1111-2222-3333-4', 'Authorized details did not use the C: context-reference display format.');
projectUiAssert($presented['details']['anchor'] === 'A:AAAA-BBBB-CCCC-DDDD', 'Authorized details did not use the A: anchor display format.');
projectUiAssert($presented['field_url'] === '/redcap/DataEntry/index.php?pid=123&id=R-002&event_id=417&page=consent&instance=1', 'Project verification did not create the data-entry field URL.');
projectUiAssert(!isset($presented['upload']) && !isset($presented['binding']), 'Raw verification payload escaped the project presenter.');
projectUiAssert(!isset($presented['details']['envelope_nonce']) && !isset($presented['details']['binding_mac']), 'Sensitive technical values escaped the allowlist.');
$printedReference = substr($captureReference, 2);
$controller->verify($printedReference);
projectUiAssert($service->lastReference === $captureReference, 'Printed capture reference was not normalized to the internal form.');
projectUiAssert(ReferenceGenerator::normalizeCaptureReference('s:' . strtolower($printedReference)) === $captureReference, 'S:-prefixed printed reference was not normalized.');
projectUiAssert(ReferenceGenerator::normalizeCaptureReference('S-' . $printedReference) === null, 'Retired S- capture-reference input was accepted.');

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

projectUiAssert(
    RedcapFieldLink::create(array(
        'pid' => 123,
        'event_id' => 417,
        'instrument' => 'consent',
        'repeat_type' => 'instrument',
        'repeat_instance' => 3
    ), 'R-002') === '/redcap/DataEntry/index.php?pid=123&id=R-002&event_id=417&page=consent&instance=3',
    'Repeating field URL did not include the repeat instance.'
);

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
$projectLinksByKey = array();
foreach ($projectLinks as $projectLink) {
    $projectLinksByKey[$projectLink['key'] ?? ''] = $projectLink;
}
projectUiAssert(count($projectLinksByKey) === 2, 'Project settings and verification links are not both configured.');
$projectSettingsLink = $projectLinksByKey['project-settings'] ?? array();
$projectVerificationLink = $projectLinksByKey['signature-verification'] ?? array();
projectUiAssert(($projectSettingsLink['url'] ?? null) === 'pages/project-settings.php', 'Project settings link is not configured.');
projectUiAssert(($projectVerificationLink['url'] ?? null) === 'pages/verify-signature.php', 'Project verification link is not configured.');
projectUiAssert(!array_key_exists('documentation', $projectSettingsLink), 'Project settings link contains an unsupported documentation configuration key.');
projectUiAssert(!array_key_exists('documentation', $projectVerificationLink), 'Project verification link contains an unsupported documentation configuration key.');
projectUiAssert(($projectSettingsLink['show-header-and-footer'] ?? false) === true, 'Project settings page does not request the REDCap layout.');
projectUiAssert(($projectVerificationLink['show-header-and-footer'] ?? false) === true, 'Project verification page does not request the REDCap layout.');
projectUiAssert(is_file(__DIR__ . '/../docs/project-user-guide.md'), 'Project verification documentation file is missing.');
$projectSettings = array();
foreach ($config['project-settings'] as $setting) {
    $projectSettings[$setting['key'] ?? ''] = $setting;
}
$backgroundModeSetting = $projectSettings['background-image-mode'] ?? array();
projectUiAssert(($backgroundModeSetting['type'] ?? null) === 'radio', 'Background image mode is not a radio project setting.');
projectUiAssert(($backgroundModeSetting['default'] ?? null) === 'redcap', 'Background image mode does not default to the REDCap logo.');
projectUiAssert(($backgroundModeSetting['hidden'] ?? false) === true, 'Background image mode is still exposed in the standard settings dialog.');
projectUiAssert(
    array_column($backgroundModeSetting['choices'] ?? array(), 'value') === array('redcap', 'custom', 'none'),
    'Background image mode choices are incomplete or out of order.'
);
$customBackgroundSetting = $projectSettings['custom-background-image'] ?? array();
projectUiAssert(($customBackgroundSetting['type'] ?? null) === 'file' && ($customBackgroundSetting['required'] ?? true) === false, 'Custom background image is not an optional file project setting.');
projectUiAssert(!array_key_exists('branchingLogic', $customBackgroundSetting), 'Custom background image is conditionally hidden instead of retained.');
projectUiAssert(($customBackgroundSetting['hidden'] ?? false) === true, 'Custom background image is still exposed in the standard settings dialog.');
$rotationSetting = $projectSettings['background-image-rotation'] ?? array();
projectUiAssert(($rotationSetting['type'] ?? null) === 'text' && ($rotationSetting['default'] ?? null) === '20' && ($rotationSetting['hidden'] ?? false) === true, 'Custom image rotation is not retained as a hidden project setting.');
foreach (array('unbound-upload-retention-days', 'public-project-reference') as $hiddenSettingKey) {
    projectUiAssert(($projectSettings[$hiddenSettingKey]['hidden'] ?? false) === true, 'Custom project setting is still exposed in the standard settings dialog: ' . $hiddenSettingKey);
}
projectUiAssert(($projectSettings['javascript-debug']['hidden'] ?? false) !== true, 'Browser debug should remain in the standard settings dialog.');
projectUiAssert(
    ($config['auth-ajax-actions'] ?? array()) === array('validate-project-settings'),
    'Project settings AJAX validation action is not configured.'
);
$english = parse_ini_file(__DIR__ . '/../lang/English.ini');
projectUiAssert(is_array($english), 'English language file is invalid.');
$german = parse_ini_file(__DIR__ . '/../lang/German.ini');
projectUiAssert(is_array($german), 'German language file is invalid.');
foreach ($english as $translationKey => $englishValue) {
    projectUiAssert(array_key_exists($translationKey, $german), 'German language file is missing an English language key: ' . $translationKey);
    projectUiAssert(is_string($german[$translationKey]) && $german[$translationKey] !== '', 'German language entry is empty: ' . $translationKey);
}
foreach ($german as $translationKey => $germanValue) {
    projectUiAssert(array_key_exists($translationKey, $english), 'German language file contains an unknown key: ' . $translationKey);
}
projectUiAssert(($english['ui_project_verification_title'] ?? null) === 'Verify watermarked signature', 'Project verification title translation is missing.');
projectUiAssert(($english['ui_documentation_prompt'] ?? null) === 'To learn more, check out the {documentation_link}.', 'Documentation prompt translation is missing.');
$translatedConfigurationKeys = array(
    $config['tt_name'] ?? null,
    $config['tt_description'] ?? null,
    $config['documentation'] ?? null,
    $config['links']['control-center'][0]['tt_name'] ?? null,
    $config['action-tags'][0]['description'] ?? null,
    $config['crons'][0]['tt_cron_description'] ?? null
);
foreach ($config['links']['project'] as $projectLink) {
    $translatedConfigurationKeys[] = $projectLink['tt_name'] ?? null;
}
foreach ($config['project-settings'] as $setting) {
    $translatedConfigurationKeys[] = ($setting['tt_name'] ?? null) === true
        ? ($setting['name'] ?? null)
        : ($setting['tt_name'] ?? null);
    foreach ($setting['choices'] ?? array() as $choice) {
        $translatedConfigurationKeys[] = ($choice['tt_name'] ?? null) === true
            ? ($choice['name'] ?? null)
            : ($choice['tt_name'] ?? null);
    }
}
foreach ($translatedConfigurationKeys as $translationKey) {
    projectUiAssert(is_string($translationKey) && array_key_exists($translationKey, $english), 'A translated configuration field has no English language entry.');
}
$localizationSources = array(
    __DIR__ . '/../WatermarkedSignaturesExternalModule.php',
    __DIR__ . '/../pages/project-settings.php',
    __DIR__ . '/../pages/verify-signature.php',
    __DIR__ . '/../pages/admin-verify-signature.php',
    __DIR__ . '/../pages/partials/verification-page.php'
);
foreach ($localizationSources as $sourcePath) {
    $source = file_get_contents($sourcePath);
    preg_match_all('/(?:\\$module|\\$this)->framework->tt\\(\\s*[\'\"]([a-z0-9_]+)[\'\"]/', $source, $matches);
    foreach ($matches[1] as $translationKey) {
        projectUiAssert(array_key_exists($translationKey, $english), 'A framework translation lookup has no English language entry: ' . $translationKey);
    }
}

$entrySource = file_get_contents(__DIR__ . '/../pages/verify-signature.php');
$settingsPageSource = file_get_contents(__DIR__ . '/../pages/project-settings.php');
$settingsScriptSource = file_get_contents(__DIR__ . '/../js/project-settings.js');
$pageSource = file_get_contents(__DIR__ . '/../pages/partials/verification-page.php');
projectUiAssert(strpos($entrySource, "'is_administrator' => false") !== false, 'Project verification entry point does not declare project scope.');
projectUiAssert(strpos($entrySource, "require __DIR__ . '/partials/verification-page.php'") !== false, 'Project verification entry point does not use the shared page partial.');
projectUiAssert(strpos($entrySource, "'documentation_url' => \$module->getUrl('docs/project-user-guide.md')") !== false, 'Project verification entry point does not link its user guide.');
projectUiAssert(strpos($entrySource, "\$module->framework->tt('ui_project_verification_guide_help')") !== false, 'Project verification entry point does not retrieve documentation help text from the language file.');
projectUiAssert(strpos($pageSource, 'method="post"') !== false, 'Verification form does not use POST.');
projectUiAssert(strpos($pageSource, 'id="sigwm-verification-documentation"') !== false, 'Verification page does not render its documentation link.');
projectUiAssert(strpos($pageSource, "\$module->framework->tt('ui_documentation_prompt')") !== false, 'Verification page does not retrieve its documentation prompt through the framework.');
projectUiAssert(strpos($pageSource, '\\ExternalModules\\ExternalModules::interpolateLanguageString(') !== false, 'Verification page does not use the raw HTML interpolation workaround.');
projectUiAssert(strpos($pageSource, "array('documentation_link' => \$documentationLink)") !== false, 'Verification page does not provide the documentation-link placeholder.');
projectUiAssert(strpos($pageSource, 'redcap_csrf_token') !== false, 'Verification form is missing the REDCap CSRF token.');
projectUiAssert(strpos($pageSource, 'type="search"') !== false, 'Verification input is not a search control.');
projectUiAssert(strpos($pageSource, '<span class="input-group-text">S:</span>') !== false, 'Verification input does not show the printed S: prefix.');
projectUiAssert(strpos($pageSource, 'placeholder="5622-9F1F-AHCA-K"') !== false, 'Verification placeholder does not match the printed reference format.');
projectUiAssert(strpos($pageSource, '<h1 class="projhdr">') !== false, 'Project verification title does not use the project-page style.');
projectUiAssert(strpos($pageSource, "captureReference.addEventListener('search'") !== false, 'Verification search clear handler is missing.');
projectUiAssert(strpos($pageSource, 'id="sigwm-verification-result"') !== false, 'Verification result wrapper is missing.');
projectUiAssert(strpos($pageSource, "result.remove()") !== false, 'Verification search clear handler does not clear the result.');
projectUiAssert(strpos($pageSource, 'Go to field') !== false, 'Verification details do not include a field-navigation link.');
projectUiAssert(strpos($settingsPageSource, 'get_project_settings_state') !== false, 'Project settings page does not retrieve the saved settings.');
projectUiAssert(strpos($settingsPageSource, 'save_project_settings') !== false, 'Project settings page does not save through the module API.');
projectUiAssert(strpos($settingsPageSource, "header('Location: '") !== false && strpos($settingsPageSource, 'true, 303') !== false, 'Project settings page does not redirect after a successful save.');
projectUiAssert(strpos($settingsPageSource, 'sigwm_settings_saved') !== false, 'Project settings page does not preserve its success message after redirecting.');
projectUiAssert(strpos($settingsPageSource, 'redcap_csrf_token') !== false, 'Project settings form is missing the REDCap CSRF token.');
projectUiAssert(strpos($settingsPageSource, 'enctype="multipart/form-data"') !== false, 'Project settings form cannot upload custom images.');
projectUiAssert(strpos($settingsPageSource, 'accept="image/png,.png"') !== false, 'Project settings form does not restrict custom uploads to PNG files.');
projectUiAssert(strpos($settingsPageSource, 'sigwm-settings-background') !== false, 'Signature background settings are not grouped into one block.');
projectUiAssert(strpos($settingsPageSource, 'col-md-6 d-flex flex-column') !== false, 'Signature background controls do not use the two-column layout.');
projectUiAssert(strpos($settingsPageSource, 'sigwm-custom-image-thumbnail') !== false, 'Project settings page does not render the custom-image thumbnail.');
projectUiAssert(strpos($settingsPageSource, 'sigwm-remove-custom-image') !== false, 'Project settings page does not provide a custom-image removal control.');
projectUiAssert(strpos($settingsPageSource, 'sigwm-custom-image-trigger') !== false, 'Project settings page does not provide an add-or-replace image action.');
projectUiAssert(strpos($settingsPageSource, 'visually-hidden') !== false, 'Project settings page still exposes the native file input.');
projectUiAssert(strpos($settingsPageSource, 'sigwm-settings-image-removal-pending') !== false, 'Project settings page does not visibly mark an image pending removal.');
projectUiAssert(strpos($settingsScriptSource, 'settings_selected_image') !== false, 'Project settings page does not identify a selected replacement image before saving.');
projectUiAssert(strpos($settingsScriptSource, "imageTrigger.addEventListener('click'") !== false, 'Project settings page does not open the hidden image chooser from its action.');
projectUiAssert(strpos($settingsScriptSource, 'remove_custom_background_image') !== false, 'Project settings script does not submit the custom-image removal request.');
projectUiAssert(strpos($settingsScriptSource, 'removeCustomImage && removeCustomImage.checked && !hasPendingCustomImage()') === false, 'Project settings script lets a selected replacement override an explicit removal.');
projectUiAssert(strpos($settingsPageSource, 'sigwm-custom-image-help-content') !== false, 'Custom-image requirements are not available to the help popover.');
projectUiAssert(($english['settings_custom_image_help'] ?? null) === 'Maximum upload size: 6 MiB. Images larger than 512 px are scaled down.', 'Custom-image upload help is not concise.');
projectUiAssert(strpos($settingsPageSource, 'type="range"') !== false, 'Project settings form does not provide a rotation control.');
projectUiAssert(strpos($settingsPageSource, "getUrl('js/ConsoleDebugLogger.js')") !== false, 'Project settings page does not load the configured debug logger.');
projectUiAssert(strpos($settingsPageSource, "getUrl('js/project-settings.js')") !== false, 'Project settings page does not load its preview script.');
projectUiAssert(strpos($settingsPageSource, 'form-control-sm') !== false, 'Project settings form does not use compact Bootstrap controls.');
projectUiAssert(strpos($settingsPageSource, 'settings_unsaved_changes') !== false, 'Project settings page does not render an unsaved-changes indicator.');
projectUiAssert(strpos($settingsPageSource, 'id="sigwm-settings-save"') !== false && strpos($settingsScriptSource, 'saveButton.disabled = !isDirty') !== false, 'Project settings page does not disable saving when no changes are pending.');
projectUiAssert(strpos($settingsPageSource, 'id="sigwm-settings-saved"') !== false && strpos($settingsScriptSource, 'savedMessage.hidden = true') !== false, 'Project settings page does not clear its save confirmation after a new change.');
projectUiAssert(strpos($settingsPageSource, 'settings_discard') !== false, 'Project settings page does not render a discard-changes action.');
projectUiAssert(strpos($settingsPageSource, '$_POST[$field]') !== false, 'Project settings page does not retain editable values after a failed save.');
projectUiAssert(strpos($settingsPageSource, 'initializeJavascriptModuleObject') !== false, 'Project settings page does not initialize the framework JavaScript module object.');
projectUiAssert(strpos($settingsPageSource, 'tt_transferToJavascriptModuleObject') !== false, 'Project settings page does not transfer validation language strings to JavaScript.');
projectUiAssert(strpos($settingsScriptSource, 'FileReader') !== false, 'Project settings preview does not load replacement images locally.');
projectUiAssert(strpos($settingsScriptSource, 'customBackgroundMode.disabled') !== false, 'Project settings script does not disable the custom background mode without an image.');
projectUiAssert(strpos($settingsScriptSource, 'updateCustomImageAvailability') !== false, 'Project settings script does not update custom-image availability.');
projectUiAssert(strpos($settingsScriptSource, "trigger.addEventListener('mouseenter'") !== false && strpos($settingsScriptSource, "trigger.addEventListener('focus'") !== false, 'Custom-image help popover does not use standard browser events.');
projectUiAssert(strpos($settingsPageSource, 'sigwm-background-rotation-reset') !== false && strpos($settingsScriptSource, "rotation.value = '0'") !== false, 'Project settings rotation cannot be reset to 0 degrees.');
projectUiAssert(strpos($settingsPageSource, 'id="sigwm-watermark-preview" width="460" height="158"') !== false, 'Project settings page does not provide the 460px WM1 preview canvas.');
projectUiAssert(strpos($settingsScriptSource, 'previewSignatureHeight = 120') !== false, 'Project settings preview does not model the signature-canvas height.');
projectUiAssert(strpos($settingsScriptSource, 'previewFooterHeight = 38') !== false, 'Project settings preview does not model the WM1 footer height.');
projectUiAssert(strpos($settingsScriptSource, 'drawBackgroundPattern') !== false, 'Project settings preview does not render the repeating background pattern.');
projectUiAssert(strpos($settingsScriptSource, 'drawIdentifierOverlay') !== false, 'Project settings preview does not render the identifier overlay.');
projectUiAssert(strpos($settingsScriptSource, "'WM1 S:5622-9F1F-AHCA-K") !== false, 'Project settings preview does not render WM1 footer identifiers.');
projectUiAssert(strpos($settingsScriptSource, 'redcapLogoUrl') !== false, 'Project settings preview does not render the REDCap-logo background.');
projectUiAssert(strpos($settingsScriptSource, 'module.ajax(config.validationAction, payload)') !== false, 'Project settings changes are not validated through the framework AJAX API.');
projectUiAssert(strpos($settingsScriptSource, 'ConsoleDebugLogger') !== false, 'Project settings script does not honor the browser-debug setting.');
projectUiAssert(strpos($settingsScriptSource, "window.addEventListener('beforeunload'") !== false, 'Project settings page does not guard against losing unsaved changes.');
projectUiAssert(strpos($settingsScriptSource, "discardUrl.searchParams.delete('sigwm_settings_saved')") !== false && strpos($settingsScriptSource, 'window.location.replace(discardUrl.toString())') !== false, 'Project settings discard action does not clear the saved confirmation before restoring saved values.');

echo "Watermarked Signatures project UI smoke tests passed.\n";
