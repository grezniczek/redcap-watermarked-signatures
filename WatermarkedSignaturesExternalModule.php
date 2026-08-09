<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule;

use Exception;
use Throwable;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\Anchor;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\BindingMac;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\CanonicalJson;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\EnvelopeSigner;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\KeyDerivation;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
use DE\RUB\WatermarkedSignaturesExternalModule\Context\SavedContext;
use DE\RUB\WatermarkedSignaturesExternalModule\Storage\LogRepository;
use DE\RUB\WatermarkedSignaturesExternalModule\Watermark\Renderer;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\AdministratorVerificationController;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\ProjectAccessPolicy;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\ProjectVerificationController;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\RedcapCurrentValueReader;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\RedcapEdocReader;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\VerificationService;

require_once "classes/ActionTagHelper.php";
require_once "classes/InjectionHelper.php";
require_once "classes/Crypto/Base32.php";
require_once "classes/Crypto/Base64Url.php";
require_once "classes/Crypto/CanonicalJson.php";
require_once "classes/Crypto/KeyDerivation.php";
require_once "classes/Crypto/EnvelopeSigner.php";
require_once "classes/Crypto/ReferenceGenerator.php";
require_once "classes/Crypto/Anchor.php";
require_once "classes/Crypto/BindingMac.php";
require_once "classes/Context/SavedContext.php";
require_once "classes/Storage/LogRepository.php";
require_once "classes/Watermark/Renderer.php";
require_once "classes/Verification/AdministratorVerificationController.php";
require_once "classes/Verification/RedcapEdocReader.php";
require_once "classes/Verification/RedcapCurrentValueReader.php";
require_once "classes/Verification/RedcapFieldLink.php";
require_once "classes/Verification/VerificationService.php";
require_once "classes/Verification/ProjectAccessPolicy.php";
require_once "classes/Verification/ProjectVerificationController.php";

class WatermarkedSignaturesExternalModule extends \ExternalModules\AbstractExternalModule
{
    private $js_debug = false;

    /** @var \Project */
    private $proj = null;
    private $project_id = null;

    const ACTIONTAG = "@WATERMARKED-SIGNATURE";
    const ENVELOPE_VERSION = 1;
    const ENVELOPE_TTL_SECONDS = 14400;
    const ENVELOPE_MAX_TTL_SECONDS = 28800;
    const CLOCK_SKEW_SECONDS = 300;
    const DEFAULT_UNBOUND_UPLOAD_RETENTION_DAYS = 90;
    const MAX_UNBOUND_UPLOAD_RETENTION_DAYS = 3650;
    const ORIGIN_DATA_ENTRY = "data_entry";
    const ORIGIN_SURVEY = "survey";
    const BACKGROUND_IMAGE_REDCAP = "redcap";
    const BACKGROUND_IMAGE_CUSTOM = "custom";
    const BACKGROUND_IMAGE_NONE = "none";
    const DEFAULT_BACKGROUND_IMAGE_ROTATION = Renderer::DEFAULT_BACKGROUND_IMAGE_ROTATION;

    #region Hooks

    function redcap_data_entry_form($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
    {
        $this->init_proj($project_id);
        $this->init_config();
        $this->inject_capture_envelopes($instrument, $event_id, self::ORIGIN_DATA_ENTRY);
    }

    function redcap_survey_page($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        $this->init_proj($project_id);
        $this->init_config();
        $this->inject_capture_envelopes($instrument, $event_id, self::ORIGIN_SURVEY);
    }

    /**
     * The signature receiver calls this hook before decoding myfile_base64.
     */
    function redcap_every_page_before_render($project_id)
    {
        if ($project_id == null) {
            return;
        }

        $this->init_proj($project_id);
        $this->init_config();
        if ($this->is_signature_upload_request()) {
            $this->intercept_signature_upload();
            return;
        }

        $this->capture_direct_record_rename();
    }

    function redcap_every_page_top($project_id)
    {
        // Skip non-project context
        if ($project_id == null) return;

        // Initialize
        $this->init_proj($project_id);
        $this->init_config();
    }

    function redcap_save_record($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        $this->init_proj($project_id);
        $this->init_config();

        $saveOrigin = $survey_hash === null ? self::ORIGIN_DATA_ENTRY : self::ORIGIN_SURVEY;
        $saveUsername = $this->current_username();

        try {
            $this->track_form_save_record_rename($record, $saveOrigin, $saveUsername);
        } catch (Throwable $exception) {
            // Rename auditing must never interfere with REDCap's successful
            // save or with the independent signature-binding path below.
            $this->safe_log_event("sigwm_error_record_rename_tracking", array(
                "record" => (string) $record,
                "technical_message" => substr($exception->getMessage(), 0, 1000)
            ));
        }

        try {
            $this->bind_saved_signatures(
                $record,
                $instrument,
                $event_id,
                $repeat_instance,
                $saveOrigin,
                $saveUsername
            );
        } catch (Throwable $exception) {
            // The record save has already succeeded. Preserve REDCap data and
            // surface the binding failure through the append-only technical log.
            $this->safe_log_event("sigwm_error_save_binding", array(
                "record" => (string) $record,
                "event_id" => (int) $event_id,
                "instrument" => (string) $instrument,
                "repeat_instance" => (int) $repeat_instance,
                "technical_message" => substr($exception->getMessage(), 0, 1000)
            ));
        }
    }

    /**
     * REDCap calls this after API token/rights authorization and before it
     * dispatches the selected legacy API action.
     */
    function redcap_module_api_before($project_id, $post)
    {
        if (!is_numeric($project_id) || (int) $project_id < 1 || !is_array($post)
            || ($post['content'] ?? null) !== 'record' || ($post['action'] ?? null) !== 'rename') {
            return null;
        }

        $requestedOldRecord = $this->record_name_from_values($post, 'record');
        $requestedNewRecord = $this->record_name_from_values($post, 'new_record_name');
        if ($requestedOldRecord === null || $requestedNewRecord === null || $requestedOldRecord === $requestedNewRecord) {
            return null;
        }

        $this->init_proj((int) $project_id);
        $this->init_config();
        $this->capture_record_rename_response($requestedOldRecord, $requestedNewRecord, 'api');
        return null;
    }

    /**
     * Runs daily. A project setting of 0 explicitly retains unbound upload
     * provenance indefinitely; unset or invalid values fall back to 90 days.
     */
    function cron_purge_unbound_upload_provenance($cronAttributes)
    {
        foreach ($this->getProjectsWithModuleEnabled() as $projectId) {
            $projectId = (int) $projectId;
            if ($projectId < 1) {
                continue;
            }

            try {
                $retentionDays = $this->unbound_upload_retention_days($projectId);
                if ($retentionDays === 0) {
                    continue;
                }

                $this->framework->setProjectId($projectId);
                $repository = new LogRepository($this, new BindingMac(KeyDerivation::derive(KeyDerivation::BINDING_INFO)));
                // EM log timestamps are written with the database's current
                // application time; use REDCap/PHP's configured local time
                // rather than serializing this cutoff as UTC.
                $cutoff = date('Y-m-d H:i:s', time() - ($retentionDays * 86400));
                $repository->purgeExpiredUnboundUploads($cutoff);
            } catch (Throwable $exception) {
                error_log('Watermarked Signatures retention cleanup failed for project ' . $projectId . ': ' . $exception->getMessage());
            }
        }
    }

    function redcap_module_link_check_display($project_id, $link)
    {
        $linkKey = $link["key"] ?? "";
        if ($linkKey === "administrator-signature-verification") {
            try {
                return $this->getUser()->isSuperUser() ? $link : null;
            } catch (Throwable $exception) {
                return null;
            }
        }
        if ($linkKey === "project-settings") {
            return $this->can_configure_project_settings($project_id) ? $link : null;
        }
        if ($linkKey !== "signature-verification") {
            return parent::redcap_module_link_check_display($project_id, $link);
        }
        if (!is_numeric($project_id) || (int) $project_id < 1) {
            return null;
        }

        try {
            $this->init_proj((int) $project_id);
            $this->init_config();
            $policy = $this->project_access_policy((int) $project_id);
            return $policy->canAccessAnyInstrument($this->configured_signature_instruments()) ? $link : null;
        } catch (Throwable $exception) {
            return null;
        }
    }

    /**
     * @param int|string $projectId
     * @return array{retention_days:int,public_project_reference:string,background_image_mode:string,background_image_rotation:int,custom_image:array{available:bool,edoc_id:string,doc_name:?string,width:?int,height:?int,sha256:?string,preview_data_url:?string}}
     */
    public function get_project_settings_state($projectId)
    {
        $projectId = $this->require_project_settings_access($projectId);
        $this->init_proj($projectId);
        $this->init_config();

        $customImage = $this->custom_background_image_details();
        return array(
            "retention_days" => $this->unbound_upload_retention_days($projectId),
            "public_project_reference" => trim((string) $this->getProjectSetting("public-project-reference")),
            "background_image_mode" => $this->background_image_mode(),
            "background_image_rotation" => $this->background_image_rotation(),
            "custom_image" => array(
                "available" => $customImage["available"],
                "edoc_id" => $customImage["edoc_id"],
                "doc_name" => $customImage["doc_name"],
                "width" => $customImage["width"],
                "height" => $customImage["height"],
                "sha256" => $customImage["available"] ? hash("sha256", $customImage["contents"]) : null,
                "preview_data_url" => $customImage["available"]
                    ? "data:image/png;base64," . base64_encode($customImage["contents"])
                    : null
            )
        );
    }

    /**
     * @param int|string $projectId
     * @param array<string,mixed> $input
     * @param array<string,mixed>|null $uploadedFile
     * @return array{ok:bool,error_key:?string,state:array}
     */
    public function save_project_settings($projectId, $input, $uploadedFile)
    {
        $projectId = $this->require_project_settings_access($projectId);
        $this->init_proj($projectId);
        $this->init_config();
        if (!is_array($input)) {
            return array("ok" => false, "error_key" => "settings_error_invalid_request", "state" => $this->get_project_settings_state($projectId));
        }

        try {
            $retentionDays = $this->validate_unbound_upload_retention_days($input["retention_days"] ?? null);
            $projectReference = $this->validate_project_settings_public_reference($input["public_project_reference"] ?? null);
            $backgroundMode = $input["background_image_mode"] ?? null;
            if (!$this->is_valid_background_image_mode($backgroundMode)) {
                throw new \InvalidArgumentException("settings_error_background_mode");
            }
            $backgroundRotation = $this->validate_background_image_rotation($input["background_image_rotation"] ?? null);
            $normalizedImage = $this->normalized_uploaded_custom_background_image($uploadedFile);
            $existingImage = $this->custom_background_image_details();
            if ($backgroundMode === self::BACKGROUND_IMAGE_CUSTOM
                && $normalizedImage === null
                && !$existingImage["available"]) {
                throw new \InvalidArgumentException("settings_error_custom_image_required");
            }

            $newEdocId = $normalizedImage === null
                ? null
                : $this->store_normalized_custom_background_image($normalizedImage, $projectId);
            $this->framework->setProjectSetting("unbound-upload-retention-days", (string) $retentionDays, $projectId);
            $this->framework->setProjectSetting("public-project-reference", $projectReference, $projectId);
            $this->framework->setProjectSetting("background-image-mode", $backgroundMode, $projectId);
            $this->framework->setProjectSetting("background-image-rotation", (string) $backgroundRotation, $projectId);
            if ($newEdocId !== null) {
                $this->framework->setProjectSetting("custom-background-image", (string) $newEdocId, $projectId);
            }

            return array("ok" => true, "error_key" => null, "state" => $this->get_project_settings_state($projectId));
        } catch (\InvalidArgumentException $exception) {
            return array("ok" => false, "error_key" => $exception->getMessage(), "state" => $this->get_project_settings_state($projectId));
        } catch (Throwable $exception) {
            $this->safe_log_event("sigwm_error_project_settings", array(
                "project_id" => $projectId,
                "technical_message" => substr($exception->getMessage(), 0, 1000)
            ));
            return array("ok" => false, "error_key" => "settings_error_save", "state" => $this->get_project_settings_state($projectId));
        }
    }

    public function get_project_verification_controller($projectId)
    {
        if (!is_numeric($projectId) || (int) $projectId < 1) {
            throw new \InvalidArgumentException("Project ID must be a positive integer.");
        }
        $projectId = (int) $projectId;
        $this->init_proj($projectId);
        $this->init_config();
        $policy = $this->project_access_policy($projectId);
        if (!$policy->canAccessAnyInstrument($this->configured_signature_instruments())) {
            throw new \RuntimeException("The current user may not access signature verification in this project.");
        }

        $bindingMac = new BindingMac(KeyDerivation::derive(KeyDerivation::BINDING_INFO));
        $repository = new LogRepository($this, $bindingMac);
        $service = new VerificationService(
            $repository,
            $bindingMac,
            new RedcapEdocReader(),
            new RedcapCurrentValueReader()
        );
        return new ProjectVerificationController($projectId, $repository, $bindingMac, $service, $policy);
    }

    public function get_administrator_verification_controller()
    {
        if (!$this->getUser()->isSuperUser()) {
            throw new \RuntimeException("Administrator access is required for global signature verification.");
        }

        $bindingMac = new BindingMac(KeyDerivation::derive(KeyDerivation::BINDING_INFO));
        $repository = new LogRepository($this, $bindingMac);
        $service = new VerificationService(
            $repository,
            $bindingMac,
            new RedcapEdocReader(),
            new RedcapCurrentValueReader()
        );
        return new AdministratorVerificationController($repository, $service);
    }

    #endregion



    #region Private Helpers

    private function bind_saved_signatures($record, $instrument, $eventId, $repeatInstance, $saveOrigin, $saveUsername)
    {
        $fields = $this->get_configured_signature_fields($instrument);
        if (empty($fields)) {
            return;
        }

        $savedContext = new SavedContext(
            $this->proj,
            $this->project_id,
            $record,
            $instrument,
            $eventId,
            $repeatInstance
        );
        $data = \REDCap::getData(array(
            "project_id" => (int) $this->project_id,
            "return_format" => "array",
            "records" => array((string) $record),
            "fields" => $fields,
            "events" => array((int) $eventId)
        ));
        $persistedValues = $savedContext->extractFieldValues($data, $fields);
        $bindingMac = new BindingMac(KeyDerivation::derive(KeyDerivation::BINDING_INFO));
        $repository = new LogRepository($this, $bindingMac);

        foreach ($persistedValues as $field => $value) {
            if ($value === null || $value === "") {
                continue;
            }
            if (!is_scalar($value) || !ctype_digit((string) $value) || (int) $value < 1) {
                $this->log_binding_error(
                    "sigwm_error_invalid_edoc_value",
                    $record,
                    $field,
                    $value,
                    "The persisted signature value is not a valid edoc ID."
                );
                continue;
            }

            $edocId = (int) $value;
            try {
                $upload = $repository->findUploadByEdocId($edocId);
                if ($upload === null) {
                    // Existing/pre-module signatures are explicitly outside scope.
                    continue;
                }

                try {
                    $this->validate_upload_for_saved_context($upload, $savedContext, $field, $edocId);
                } catch (\UnexpectedValueException $exception) {
                    $this->log_binding_error(
                        "sigwm_error_scope_mismatch",
                        $record,
                        $field,
                        $edocId,
                        $exception->getMessage()
                    );
                    continue;
                }
                $binding = array_merge(
                    array(
                        "v" => 1,
                        "anchor" => $upload["anchor"],
                        "capture_ref" => $upload["capture_ref"],
                        "context_ref" => $upload["context_ref"],
                        "record_ref" => $upload["record_ref"] ?? null,
                        "project_reference" => $upload["project_reference"] ?? null,
                        "capture_origin" => $upload["capture_origin"],
                        "capture_username" => $upload["capture_username"],
                        "save_origin" => $saveOrigin,
                        "save_username" => $saveUsername,
                        "edoc_id" => $edocId,
                        "file_sha256" => $upload["file_sha256"],
                        "watermark_version" => (int) $upload["watermark_version"]
                    ),
                    $savedContext->bindingValues($field),
                    array("bound_at" => $this->utc_now())
                );
                $repository->bindOnce($binding);
            } catch (Throwable $exception) {
                $this->log_binding_error(
                    "sigwm_error_binding",
                    $record,
                    $field,
                    $edocId,
                    $exception->getMessage()
                );
            }
        }
    }

    private function validate_upload_for_saved_context($upload, SavedContext $savedContext, $field, $edocId)
    {
        $context = $savedContext->bindingValues($field);
        $matches = isset($upload["pid"], $upload["event_id"], $upload["instrument"], $upload["field"], $upload["edoc_id"])
            && (int) $upload["pid"] === $context["pid"]
            && (int) $upload["event_id"] === $context["event_id"]
            && (string) $upload["instrument"] === $context["instrument"]
            && (string) $upload["field"] === $context["field"]
            && (int) $upload["edoc_id"] === (int) $edocId;
        if (!$matches) {
            throw new \UnexpectedValueException("Upload provenance does not match the saved signature scope.");
        }
        if ((int) ($upload["watermark_version"] ?? 0) !== Renderer::VERSION) {
            throw new \UnexpectedValueException("Unsupported upload watermark version.");
        }
        if (!isset($upload["file_sha256"]) || !preg_match('/^[a-f0-9]{64}$/', $upload["file_sha256"])) {
            throw new \UnexpectedValueException("Upload provenance contains an invalid file digest.");
        }
        if (!isset($upload["capture_origin"]) || !$this->is_valid_origin($upload["capture_origin"])) {
            throw new \UnexpectedValueException("Upload provenance contains an invalid capture origin.");
        }
        if (!array_key_exists("capture_username", $upload)
            || ($upload["capture_username"] !== null && !is_string($upload["capture_username"]))) {
            throw new \UnexpectedValueException("Upload provenance contains an invalid capture username.");
        }
        if (!array_key_exists("project_reference", $upload)
            || !$this->is_valid_public_project_reference($upload["project_reference"])) {
            throw new \UnexpectedValueException("Upload provenance contains an invalid public project reference.");
        }
        if (array_key_exists("background_image_mode", $upload)
            && !$this->is_valid_background_image_mode($upload["background_image_mode"])) {
            throw new \UnexpectedValueException("Upload provenance contains an invalid selected background image mode.");
        }
        if (array_key_exists("background_image_effective_mode", $upload)
            && !$this->is_valid_background_image_mode($upload["background_image_effective_mode"])) {
            throw new \UnexpectedValueException("Upload provenance contains an invalid applied background image mode.");
        }
        if (array_key_exists("background_image_sha256", $upload)
            && $upload["background_image_sha256"] !== null
            && (!is_string($upload["background_image_sha256"])
                || !preg_match('/^[a-f0-9]{64}$/', $upload["background_image_sha256"]))) {
            throw new \UnexpectedValueException("Upload provenance contains an invalid background image digest.");
        }
        if (array_key_exists("background_image_rotation", $upload)
            && !$this->is_valid_background_image_rotation($upload["background_image_rotation"])) {
            throw new \UnexpectedValueException("Upload provenance contains an invalid background image rotation.");
        }

        $scope = array(
            "v" => (int) $upload["watermark_version"],
            "pid" => $context["pid"],
            "event_id" => $context["event_id"],
            "instrument" => $context["instrument"],
            "field" => $context["field"]
        );
        $expectedAnchor = Anchor::create($scope, KeyDerivation::derive(KeyDerivation::ANCHOR_INFO));
        if (!isset($upload["anchor"]) || !hash_equals($expectedAnchor, (string) $upload["anchor"])) {
            throw new \UnexpectedValueException("Upload provenance anchor does not match the saved signature scope.");
        }
    }

    private function log_binding_error($eventType, $record, $field, $edocId, $message)
    {
        $this->safe_log_event($eventType, array(
            "record" => (string) $record,
            "field" => (string) $field,
            "edoc_id" => is_scalar($edocId) ? (string) $edocId : "",
            "technical_message" => substr((string) $message, 0, 1000)
        ));
    }

    private function safe_log_event($eventType, $parameters)
    {
        try {
            return $this->log($eventType, $parameters);
        } catch (Throwable $exception) {
            error_log("Watermarked Signatures logging failed ({$eventType}): " . $exception->getMessage());
            return null;
        }
    }

    private function utc_now()
    {
        $now = new \DateTimeImmutable("now", new \DateTimeZone("UTC"));
        return $now->format("Y-m-d\\TH:i:s.v\\Z");
    }

    private function current_username()
    {
        $username = null;
        if (class_exists("\\ExternalModules\\ExternalModules")
            && method_exists("\\ExternalModules\\ExternalModules", "getUsername")) {
            $username = \ExternalModules\ExternalModules::getUsername();
        } elseif (defined("USERID")) {
            $username = USERID;
        }

        return $username === null || $username === "" ? null : (string) $username;
    }

    private function track_form_save_record_rename($record, $saveOrigin, $saveUsername)
    {
        if ($saveOrigin !== self::ORIGIN_DATA_ENTRY || !isset($_POST['__old_id__']) || isset($_POST['__rename_failed__'])) {
            return;
        }

        $oldRecord = trim(html_entity_decode((string) $_POST['__old_id__'], ENT_QUOTES));
        $newRecord = (string) $record;
        if ($oldRecord === '' || $newRecord === '' || $oldRecord === $newRecord) {
            return;
        }

        $repository = new LogRepository($this, new BindingMac(KeyDerivation::derive(KeyDerivation::BINDING_INFO)));
        // REDCap has already renamed the indexed record column by the time
        // redcap_save_record runs. If no signature binding moved with it,
        // there is no module history that needs a durable rename event.
        $boundNewRecord = $repository->findBoundRecordId($newRecord);
        if ($boundNewRecord === null) {
            return;
        }

        $this->append_record_rename_event(
            $repository,
            $oldRecord,
            $boundNewRecord,
            'data_entry_form_save',
            $saveUsername
        );
    }

    /**
     * Capture REDCap's record-home rename route only after its controller
     * returns success. There is no dedicated External Module hook for this
     * route in REDCap 17.3, so the response is the server-side confirmation
     * that the trusted route completed its rename.
     */
    private function capture_direct_record_rename()
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
            || ($_GET['route'] ?? '') !== 'DataEntryController:renameRecord') {
            return;
        }

        $requestedOldRecord = $this->posted_record_name('record');
        $requestedNewRecord = $this->posted_record_name('new_record');
        if ($requestedOldRecord === null || $requestedNewRecord === null || $requestedOldRecord === $requestedNewRecord) {
            return;
        }

        $this->capture_record_rename_response($requestedOldRecord, $requestedNewRecord, 'data_entry_record_home');
    }

    /**
     * Begin observing a trusted REDCap rename response. The caller must run
     * before the core rename operation; a success response is the evidence
     * that the change actually completed.
     */
    private function capture_record_rename_response($requestedOldRecord, $requestedNewRecord, $renameOrigin)
    {
        try {
            $repository = new LogRepository($this, new BindingMac(KeyDerivation::derive(KeyDerivation::BINDING_INFO)));
            // Resolve the stored spelling before REDCap changes the record.
            // This also makes the capture a no-op for records with no module
            // binding to preserve.
            $oldRecord = $repository->findBoundRecordId($requestedOldRecord);
            if ($oldRecord === null) {
                return;
            }
        } catch (Throwable $exception) {
            $this->safe_log_event('sigwm_error_record_rename_tracking', array(
                'record' => $requestedOldRecord,
                'technical_message' => substr($exception->getMessage(), 0, 1000)
            ));
            return;
        }

        $module = $this;
        $renameUsername = $this->current_username();
        ob_start(function ($output) use ($module, $oldRecord, $requestedNewRecord, $renameOrigin, $renameUsername) {
            if (trim($output) === '1') {
                try {
                    $repository = new LogRepository($module, new BindingMac(KeyDerivation::derive(KeyDerivation::BINDING_INFO)));
                    // Looking this up after the controller completed gives us
                    // REDCap's final spelling in the multi-arm case.
                    $newRecord = $repository->findBoundRecordId($requestedNewRecord);
                    if ($newRecord !== null) {
                        $module->append_record_rename_event(
                            $repository,
                            $oldRecord,
                            $newRecord,
                            $renameOrigin,
                            $renameUsername
                        );
                    }
                } catch (Throwable $exception) {
                    $module->safe_log_event('sigwm_error_record_rename_tracking', array(
                        'record' => $oldRecord,
                        'technical_message' => substr($exception->getMessage(), 0, 1000)
                    ));
                }
            }
            return $output;
        });

        // The EM framework closes its topmost hook buffer on return. Keep an
        // inert guard above the response observer, as with upload provenance.
        ob_start();
    }

    private function posted_record_name($key)
    {
        return $this->record_name_from_values($_POST, $key);
    }

    private function record_name_from_values($values, $key)
    {
        if (!is_array($values) || !isset($values[$key]) || !is_scalar($values[$key])) {
            return null;
        }
        $record = trim((string) $values[$key]);
        return $record === '' ? null : $record;
    }

    private function append_record_rename_event(LogRepository $repository, $oldRecord, $newRecord, $renameOrigin, $renameUsername)
    {
        if ($oldRecord === $newRecord) {
            return;
        }

        $repository->appendRecordRename(array(
            'v' => 1,
            'pid' => (int) $this->project_id,
            'old_record_id' => (string) $oldRecord,
            'new_record_id' => (string) $newRecord,
            'rename_origin' => (string) $renameOrigin,
            'rename_username' => $renameUsername,
            'renamed_at' => $this->utc_now()
        ));
    }

    private function is_valid_origin($origin)
    {
        return $origin === self::ORIGIN_DATA_ENTRY || $origin === self::ORIGIN_SURVEY;
    }

    private function inject_capture_envelopes($instrument, $event_id, $captureOrigin)
    {
        if (!$this->is_valid_origin($captureOrigin)) {
            throw new \InvalidArgumentException("Invalid signature capture origin.");
        }
        $fields = $this->get_configured_signature_fields($instrument);
        if (empty($fields)) {
            return;
        }

        $now = time();
        $signer = new EnvelopeSigner(KeyDerivation::derive(KeyDerivation::ENVELOPE_INFO));
        $envelopes = array();

        foreach ($fields as $field) {
            $payload = array(
                "v" => self::ENVELOPE_VERSION,
                "pid" => (int) $this->project_id,
                "event_id" => (int) $event_id,
                "instrument" => (string) $instrument,
                "field" => (string) $field,
                "capture_origin" => $captureOrigin,
                "context_ref" => ReferenceGenerator::contextReference(),
                // Do not capture REDCap's tentative new-record value. The
                // authoritative record ID is attached only after a successful
                // save. Stable record pseudonyms are intentionally deferred.
                "record_ref" => null,
                "project_reference" => $this->public_project_reference(),
                "issued_at" => $now,
                "expires_at" => $now + self::ENVELOPE_TTL_SECONDS,
                "nonce" => ReferenceGenerator::nonce(),
                "purpose" => "signature"
            );
            $envelopes[$field] = $signer->sign($payload);
        }

        $config = json_encode(
            array(
                "envelopes" => $envelopes,
                "debug" => $this->js_debug
            ),
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
        );

        echo "<script type=\"text/javascript\">window.REDCapSignatureWatermark={$config};</script>";
        InjectionHelper::init($this)->js("js/signature-watermark.js");
    }

    private function intercept_signature_upload()
    {
        if (($_SERVER["REQUEST_METHOD"] ?? "") !== "POST") {
            return;
        }

        $field = $this->posted_field_name();
        if ($field === null) {
            return;
        }

        $metadata = $this->get_project_metadata();
        if (!isset($metadata[$field]) || !$this->is_configured_signature_field($metadata[$field])) {
            return;
        }

        $envelope = isset($_POST["sigwm_envelope"]) ? (string) $_POST["sigwm_envelope"] : "";
        if ($envelope === "") {
            $this->fail_upload($field, "sigwm_error_invalid_envelope", "The signed watermark envelope is missing.");
            return;
        }

        try {
            $signer = new EnvelopeSigner(KeyDerivation::derive(KeyDerivation::ENVELOPE_INFO));
            $payload = $signer->verify($envelope);
            $this->validate_envelope_payload($payload, $field, $metadata[$field]);
        } catch (Throwable $exception) {
            $this->fail_upload($field, "sigwm_error_invalid_envelope", $exception->getMessage());
            return;
        }

        $scope = array(
            "v" => Renderer::VERSION,
            "pid" => (int) $payload["pid"],
            "event_id" => (int) $payload["event_id"],
            "instrument" => (string) $payload["instrument"],
            "field" => (string) $payload["field"]
        );
        $anchor = Anchor::create($scope, KeyDerivation::derive(KeyDerivation::ANCHOR_INFO));
        $captureReference = ReferenceGenerator::captureReference();
        $capturedAt = gmdate("Y-m-d\TH:i:s\Z");

        try {
            $backgroundImage = $this->background_image_profile();
            $renderer = new Renderer();
            $watermarkedPng = $renderer->renderBase64(
                isset($_POST["myfile_base64"]) ? $_POST["myfile_base64"] : "",
                $anchor,
                $payload["context_ref"],
                $captureReference,
                $capturedAt,
                $payload["project_reference"],
                $backgroundImage
            );
        } catch (Throwable $exception) {
            $this->fail_upload($field, "sigwm_error_upload_render", $exception->getMessage());
            return;
        }

        $_POST["myfile_base64"] = base64_encode($watermarkedPng);
        $provenance = array(
            "v" => 1,
            "capture_ref" => $captureReference,
            "context_ref" => $payload["context_ref"],
            "record_ref" => isset($payload["record_ref"]) ? $payload["record_ref"] : null,
            "project_reference" => $payload["project_reference"],
            "capture_origin" => $payload["capture_origin"],
            "capture_username" => $this->current_username(),
            "anchor" => $anchor,
            "pid" => (int) $payload["pid"],
            "event_id" => (int) $payload["event_id"],
            "instrument" => $payload["instrument"],
            "field" => $payload["field"],
            "captured_at" => $capturedAt,
            "file_sha256" => hash("sha256", $watermarkedPng),
            "envelope_nonce" => $payload["nonce"],
            "watermark_version" => Renderer::VERSION,
            "background_image_mode" => $backgroundImage["requested_mode"],
            "background_image_effective_mode" => $backgroundImage["mode"],
            "background_image_sha256" => $backgroundImage["sha256"],
            "background_image_rotation" => $backgroundImage["rotation"]
        );

        $this->capture_edoc_id_from_response($field, $provenance);
    }

    private function validate_envelope_payload($payload, $postedField, $fieldMetadata)
    {
        $required = array(
            "v", "pid", "event_id", "instrument", "field", "context_ref",
            "record_ref", "project_reference", "capture_origin", "issued_at", "expires_at", "nonce", "purpose"
        );
        foreach ($required as $key) {
            if (!array_key_exists($key, $payload)) {
                throw new \UnexpectedValueException("Envelope property '{$key}' is missing.");
            }
        }

        if ($payload["v"] !== self::ENVELOPE_VERSION || $payload["purpose"] !== "signature") {
            throw new \UnexpectedValueException("Unsupported signature watermark envelope.");
        }
        if (!is_int($payload["pid"]) || $payload["pid"] !== (int) $this->project_id) {
            throw new \UnexpectedValueException("Envelope project mismatch.");
        }
        if (!is_int($payload["event_id"]) || !$this->proj->validateEventId($payload["event_id"])) {
            throw new \UnexpectedValueException("Envelope event mismatch.");
        }
        $requestEventId = isset($_GET["event_id"]) && is_numeric($_GET["event_id"])
            ? (int) $_GET["event_id"]
            : null;
        if ($requestEventId === null || $payload["event_id"] !== $requestEventId) {
            throw new \UnexpectedValueException("Envelope event does not match the upload request.");
        }
        if (!is_string($payload["instrument"]) || $payload["instrument"] !== $fieldMetadata["form_name"]) {
            throw new \UnexpectedValueException("Envelope instrument mismatch.");
        }
        if (isset($_GET["page"]) && $_GET["page"] !== "" && $payload["instrument"] !== (string) $_GET["page"]) {
            throw new \UnexpectedValueException("Envelope instrument does not match the upload request.");
        }
        if (!$this->proj->validateFormEvent($payload["instrument"], $payload["event_id"])) {
            throw new \UnexpectedValueException("The envelope instrument is not assigned to the event.");
        }
        if (!is_string($payload["field"]) || $payload["field"] !== $postedField) {
            throw new \UnexpectedValueException("Envelope field mismatch.");
        }
        if (!$this->is_valid_origin($payload["capture_origin"])) {
            throw new \UnexpectedValueException("Invalid envelope capture origin.");
        }
        if (!is_string($payload["context_ref"]) || !preg_match('/^C:[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]$/', $payload["context_ref"])) {
            throw new \UnexpectedValueException("Invalid envelope context reference.");
        }
        if ($payload["record_ref"] !== null
            && (!is_string($payload["record_ref"]) || !preg_match('/^R-[0-9A-HJKMNP-TV-Z-]+$/', $payload["record_ref"]))) {
            throw new \UnexpectedValueException("Invalid envelope record reference.");
        }
        if (!$this->is_valid_public_project_reference($payload["project_reference"])) {
            throw new \UnexpectedValueException("Invalid envelope public project reference.");
        }
        if (!is_string($payload["nonce"]) || !preg_match('/^[A-Za-z0-9_-]{20,64}$/', $payload["nonce"])) {
            throw new \UnexpectedValueException("Invalid envelope nonce.");
        }
        if (!is_int($payload["issued_at"]) || !is_int($payload["expires_at"])) {
            throw new \UnexpectedValueException("Invalid envelope timestamps.");
        }

        $now = time();
        if ($payload["issued_at"] > $now + self::CLOCK_SKEW_SECONDS) {
            throw new \UnexpectedValueException("The signature watermark envelope is not valid yet.");
        }
        if ($payload["expires_at"] < $now) {
            throw new \UnexpectedValueException("The signature watermark envelope has expired.");
        }
        if ($payload["expires_at"] <= $payload["issued_at"]) {
            throw new \UnexpectedValueException("The signature watermark envelope lifetime is invalid.");
        }
        if (($payload["expires_at"] - $payload["issued_at"]) > self::ENVELOPE_MAX_TTL_SECONDS) {
            throw new \UnexpectedValueException("The signature watermark envelope lifetime is invalid.");
        }
    }

    private function capture_edoc_id_from_response($field, $provenance)
    {
        $module = $this;
        $recorded = false;
        $responseFailureLogged = false;
        $fieldPattern = preg_quote($field, '/');

        ob_start(function ($output) use ($module, &$recorded, &$responseFailureLogged, $fieldPattern, $provenance) {
            if (!$recorded && preg_match(
                "/stopUpload\\(\\s*1\\s*,\\s*(['\"])${fieldPattern}\\1\\s*,\\s*(['\"])([1-9][0-9]*)\\2/",
                $output,
                $matches
            )) {
                $recorded = true;
                $event = $provenance;
                $event["edoc_id"] = (int) $matches[3];
                $module->append_upload_provenance($event);
            } elseif (!$recorded && !$responseFailureLogged
                && preg_match('/stopUpload\\(\\s*1\\b/', $output)) {
                // We know REDCap reported an upload success, but did not
                // recognize a trusted edoc ID for this field. Without an
                // upload event, save-time binding will (correctly) refuse to
                // treat the edoc as module-managed, so retain a durable clue
                // for administrators instead of silently losing provenance.
                $responseFailureLogged = true;
                $module->log_upload_provenance_failure(
                    'sigwm_error_upload_provenance_response',
                    $provenance,
                    'REDCap reported a successful signature upload, but its edoc ID response could not be parsed.'
                );
            }
            return $output;
        });

        // The EM framework wraps each hook invocation in its own output buffer
        // and unconditionally closes the topmost buffer when the hook returns.
        // Leave this inert guard on top so the provenance buffer above remains
        // active until file_upload.php prints REDCap's stopUpload() response.
        ob_start();
    }

    public function append_upload_provenance($event)
    {
        try {
            $this->log("sigwm_upload", array(
                "capture_ref" => $event["capture_ref"],
                "context_ref" => $event["context_ref"],
                "project_reference" => $event["project_reference"],
                "capture_origin" => $event["capture_origin"],
                "capture_username" => $event["capture_username"],
                "anchor" => $event["anchor"],
                "event_id" => $event["event_id"],
                "instrument" => $event["instrument"],
                "field" => $event["field"],
                "edoc_id" => $event["edoc_id"],
                "file_sha256" => $event["file_sha256"],
                "watermark_version" => $event["watermark_version"],
                "payload_json" => CanonicalJson::encode($event)
            ));
            return true;
        } catch (Throwable $exception) {
            error_log("Watermarked Signatures provenance logging failed: " . $exception->getMessage());
            // The primary provenance row could not be written after REDCap
            // created the edoc. Make a second, smaller best-effort log entry
            // that lets an administrator identify the affected capture and
            // investigate/recover it. safe_log_event() preserves error_log as
            // a final fallback if the log table itself remains unavailable.
            $this->log_upload_provenance_failure(
                'sigwm_error_upload_provenance_logging',
                $event,
                'REDCap created a signature edoc, but its upload provenance could not be logged: ' . $exception->getMessage()
            );
            return false;
        }
    }

    /**
     * Record enough non-secret context to investigate a provenance failure.
     * This deliberately excludes the signed-envelope nonce and image bytes.
     */
    private function log_upload_provenance_failure($eventType, $provenance, $technicalMessage)
    {
        $parameters = array(
            'capture_ref' => is_array($provenance) ? ($provenance['capture_ref'] ?? '') : '',
            'context_ref' => is_array($provenance) ? ($provenance['context_ref'] ?? '') : '',
            'anchor' => is_array($provenance) ? ($provenance['anchor'] ?? '') : '',
            'event_id' => is_array($provenance) ? ($provenance['event_id'] ?? '') : '',
            'instrument' => is_array($provenance) ? ($provenance['instrument'] ?? '') : '',
            'field' => is_array($provenance) ? ($provenance['field'] ?? '') : '',
            'edoc_id' => is_array($provenance) ? ($provenance['edoc_id'] ?? '') : '',
            'technical_message' => substr((string) $technicalMessage, 0, 1000)
        );
        $this->safe_log_event($eventType, $parameters);
    }

    private function fail_upload($field, $eventType, $technicalMessage)
    {
        try {
            $this->log($eventType, array(
                "field" => $field,
                "event_id" => isset($_GET["event_id"]) && is_numeric($_GET["event_id"]) ? (int) $_GET["event_id"] : "",
                "technical_message" => substr((string) $technicalMessage, 0, 1000)
            ));
        } catch (Throwable $exception) {
            error_log("Watermarked Signatures error logging failed: " . $exception->getMessage());
        }

        $message = $this->framework->tt('ui_upload_watermark_failed'); // The signature could not be securely watermarked. Please reopen the signature dialog and try again.
        $fieldJson = json_encode($field);
        $messageJson = json_encode($message);
        $instance = isset($_GET["instance"]) && is_numeric($_GET["instance"]) && (int) $_GET["instance"] > 0
            ? (int) $_GET["instance"]
            : 1;
        echo "<script type=\"text/javascript\">
            window.parent.window.stopUpload(0, {$fieldJson}, '0', '', '', '', '', '', '', {$instance}, true);
            window.parent.window.alert({$messageJson});
        </script>";
        $this->exitAfterHook();
    }

    private function is_signature_upload_request()
    {
        $page = defined("PAGE") ? (string) PAGE : "";
        $passthru = isset($_GET["__passthru"]) ? rawurldecode((string) $_GET["__passthru"]) : "";

        return $page === "DataEntry/file_upload.php"
            || substr($page, -strlen("/DataEntry/file_upload.php")) === "/DataEntry/file_upload.php"
            || $passthru === "DataEntry/file_upload.php";
    }

    private function posted_field_name()
    {
        if (!isset($_POST["field_name"]) || !is_string($_POST["field_name"])) {
            return null;
        }

        $field = explode("-", $_POST["field_name"], 2)[0];
        if (!preg_match('/^[a-z][a-z0-9_]*$/i', $field)) {
            return null;
        }

        return $field;
    }

    private function get_configured_signature_fields($instrument)
    {
        $fields = array();
        foreach ($this->get_project_metadata() as $field => $metadata) {
            if (($metadata["form_name"] ?? null) === $instrument && $this->is_configured_signature_field($metadata)) {
                $fields[] = $field;
            }
        }
        return $fields;
    }

    private function configured_signature_instruments()
    {
        $instruments = array();
        foreach ($this->get_project_metadata() as $metadata) {
            if ($this->is_configured_signature_field($metadata) && isset($metadata["form_name"])) {
                $instruments[] = (string) $metadata["form_name"];
            }
        }
        return array_values(array_unique($instruments));
    }

    private function project_access_policy($projectId)
    {
        $user = $this->getUser();
        $module = $this;
        return new ProjectAccessPolicy(
            (int) $projectId,
            $user->isSuperUser(),
            $user->getRights((int) $projectId),
            function ($record) use ($module) {
                return $module->getDAG($record);
            }
        );
    }

    private function is_configured_signature_field($metadata)
    {
        if (($metadata["element_type"] ?? null) !== "file") {
            return false;
        }
        if (!in_array($metadata["element_validation_type"] ?? null, array("signature", "enhanced_signature"), true)) {
            return false;
        }

        $annotation = isset($metadata["misc"]) ? $metadata["misc"] : ($metadata["field_annotation"] ?? "");
        $tags = ActionTagHelper::parseActionTags((string) $annotation, self::ACTIONTAG);
        return is_array($tags) && count($tags) > 0;
    }

    private function get_project_metadata()
    {
        if (class_exists("\\Design") && \Design::isDraftPreview() && !empty($this->proj->metadata_temp)) {
            return $this->proj->metadata_temp;
        }
        return $this->proj->metadata;
    }

    private function init_proj($project_id)
    {
        if ($this->proj == null) {
            $this->proj = new \Project($project_id);
            $this->project_id = $project_id;
        }
    }

    private function require_proj()
    {
        if ($this->proj == null) {
            throw new Exception($this->framework->tt('error_project_not_initialized')); // Project is not initialized.
        }
    }

    private function init_config()
    {
        $this->require_proj();
        $setting = $this->getProjectSetting("javascript-debug");
        $this->js_debug = $setting == true;
    }

    /**
     * The public reference is deliberately a constrained ASCII presentation
     * value: it is rendered by GD and becomes visible in every exported image.
     * It is not a REDCap project ID, title, or a security identifier.
     */
    private function public_project_reference()
    {
        $reference = trim((string) $this->getProjectSetting('public-project-reference'));
        if ($reference === '') {
            return null;
        }
        if (!$this->is_valid_public_project_reference($reference)) {
            throw new \UnexpectedValueException(
                'The public project reference must be 1–30 ASCII letters, digits, spaces, dots, hyphens, underscores, or slashes.'
            );
        }
        return $reference;
    }

    /**
     * Resolve the project-owned asset immediately before rendering. The stored
     * digest describes the exact file used even when an administrator later
     * replaces the retained setting.
     */
    private function background_image_profile()
    {
        $requestedMode = $this->background_image_mode();
        if ($requestedMode !== self::BACKGROUND_IMAGE_CUSTOM) {
            return array(
                "mode" => $requestedMode,
                "requested_mode" => $requestedMode,
                "contents" => null,
                "sha256" => null,
                "rotation" => $requestedMode === self::BACKGROUND_IMAGE_NONE
                    ? 0
                    : self::DEFAULT_BACKGROUND_IMAGE_ROTATION
            );
        }

        $image = array("edoc_id" => "");
        try {
            $image = $this->custom_background_image_details();
            if (!$image["available"]) {
                throw new \UnexpectedValueException($image["technical_message"]);
            }
            return array(
                "mode" => self::BACKGROUND_IMAGE_CUSTOM,
                "requested_mode" => self::BACKGROUND_IMAGE_CUSTOM,
                "contents" => $image["contents"],
                "sha256" => hash("sha256", $image["contents"]),
                "rotation" => $this->background_image_rotation()
            );
        } catch (Throwable $exception) {
            // Do not block a signature because an optional presentation asset
            // is unavailable. The provenance distinguishes the selection from
            // the REDCap-logo fallback used for this individual capture.
            $this->safe_log_event("sigwm_error_background_image", array(
                "project_id" => (int) $this->project_id,
                "background_image_mode" => self::BACKGROUND_IMAGE_CUSTOM,
                "background_image_effective_mode" => self::BACKGROUND_IMAGE_REDCAP,
                "background_image_edoc_id" => $image["edoc_id"] ?? "",
                "technical_message" => substr($exception->getMessage(), 0, 1000)
            ));
            return array(
                "mode" => self::BACKGROUND_IMAGE_REDCAP,
                "requested_mode" => self::BACKGROUND_IMAGE_CUSTOM,
                "contents" => null,
                "sha256" => null,
                "rotation" => self::DEFAULT_BACKGROUND_IMAGE_ROTATION
            );
        }
    }

    private function custom_background_image_details()
    {
        $edocId = $this->getProjectSetting("custom-background-image");
        $details = array(
            "available" => false,
            "edoc_id" => is_scalar($edocId) ? (string) $edocId : "",
            "doc_name" => null,
            "width" => null,
            "height" => null,
            "contents" => null,
            "technical_message" => "No custom background image is configured."
        );
        if (!is_scalar($edocId) || !ctype_digit((string) $edocId) || (int) $edocId < 1) {
            return $details;
        }

        try {
            $image = (new RedcapEdocReader())->read(
                (int) $edocId,
                (int) $this->project_id,
                Renderer::MAX_CUSTOM_BACKGROUND_IMAGE_BYTES
            );
            if (empty($image["exists"]) || empty($image["readable"]) || !isset($image["contents"])) {
                throw new \UnexpectedValueException("The custom background image could not be read from REDCap storage.");
            }
            $dimensions = Renderer::validateCustomBackgroundImage($image["contents"]);
            $details["available"] = true;
            $details["doc_name"] = $image["doc_name"];
            $details["width"] = $dimensions["width"];
            $details["height"] = $dimensions["height"];
            $details["contents"] = $image["contents"];
            $details["technical_message"] = null;
        } catch (Throwable $exception) {
            $details["technical_message"] = $exception->getMessage();
        }
        return $details;
    }

    private function background_image_mode()
    {
        $mode = $this->getProjectSetting("background-image-mode");
        return $this->is_valid_background_image_mode($mode)
            ? $mode
            : self::BACKGROUND_IMAGE_REDCAP;
    }

    private function background_image_rotation()
    {
        $rotation = $this->getProjectSetting("background-image-rotation");
        return $this->is_valid_background_image_rotation($rotation)
            ? (int) $rotation
            : self::DEFAULT_BACKGROUND_IMAGE_ROTATION;
    }

    private function is_valid_background_image_rotation($rotation)
    {
        if (is_int($rotation)) {
            $value = $rotation;
        } elseif (is_string($rotation) && preg_match('/^-?(?:0|[1-9][0-9]{0,2})$/D', $rotation)) {
            $value = (int) $rotation;
        } else {
            return false;
        }
        return $value >= Renderer::MIN_BACKGROUND_IMAGE_ROTATION
            && $value <= Renderer::MAX_BACKGROUND_IMAGE_ROTATION;
    }

    private function validate_unbound_upload_retention_days($value)
    {
        if (!is_string($value) || !ctype_digit($value)) {
            throw new \InvalidArgumentException("settings_error_retention_days");
        }
        $days = (int) $value;
        if ($days > self::MAX_UNBOUND_UPLOAD_RETENTION_DAYS) {
            throw new \InvalidArgumentException("settings_error_retention_days");
        }
        return $days;
    }

    private function validate_project_settings_public_reference($value)
    {
        if (!is_string($value)) {
            throw new \InvalidArgumentException("settings_error_public_project_reference");
        }
        $reference = trim($value);
        if ($reference !== "" && !$this->is_valid_public_project_reference($reference)) {
            throw new \InvalidArgumentException("settings_error_public_project_reference");
        }
        return $reference;
    }

    private function validate_background_image_rotation($value)
    {
        if (!$this->is_valid_background_image_rotation($value)) {
            throw new \InvalidArgumentException("settings_error_background_rotation");
        }
        return (int) $value;
    }

    private function normalized_uploaded_custom_background_image($uploadedFile)
    {
        if (!is_array($uploadedFile) || !array_key_exists("error", $uploadedFile)) {
            return null;
        }
        if (!is_int($uploadedFile["error"]) && !ctype_digit((string) $uploadedFile["error"])) {
            throw new \InvalidArgumentException("settings_error_image_upload");
        }
        $error = (int) $uploadedFile["error"];
        if ($error === UPLOAD_ERR_NO_FILE) {
            return null;
        }
        if ($error !== UPLOAD_ERR_OK) {
            throw new \InvalidArgumentException("settings_error_image_upload");
        }
        if (!isset($uploadedFile["size"]) || !is_numeric($uploadedFile["size"])
            || (int) $uploadedFile["size"] < 1
            || (int) $uploadedFile["size"] > Renderer::MAX_CUSTOM_BACKGROUND_IMAGE_UPLOAD_BYTES) {
            throw new \InvalidArgumentException("settings_error_image_upload_size");
        }
        if (!isset($uploadedFile["tmp_name"]) || !is_string($uploadedFile["tmp_name"]) || !is_file($uploadedFile["tmp_name"])) {
            throw new \InvalidArgumentException("settings_error_image_upload");
        }

        $contents = @file_get_contents($uploadedFile["tmp_name"]);
        if (!is_string($contents) || $contents === "") {
            throw new \InvalidArgumentException("settings_error_image_upload");
        }
        try {
            return Renderer::normalizeCustomBackgroundImage($contents);
        } catch (Throwable $exception) {
            throw new \InvalidArgumentException("settings_error_image_invalid");
        }
    }

    private function store_normalized_custom_background_image($contents, $projectId)
    {
        $temporaryPath = tempnam(sys_get_temp_dir(), "sigwm-");
        if ($temporaryPath === false) {
            throw new \RuntimeException("Could not create a temporary custom background image.");
        }
        try {
            if (@file_put_contents($temporaryPath, $contents) !== strlen($contents)) {
                throw new \RuntimeException("Could not write the normalized custom background image.");
            }
            $edocId = \Files::uploadFile(array(
                "name" => "watermarked-signature-background.png",
                "tmp_name" => $temporaryPath,
                "size" => strlen($contents)
            ), $projectId);
            if (!is_numeric($edocId) || (int) $edocId < 1) {
                throw new \RuntimeException("REDCap could not store the normalized custom background image.");
            }
            return (int) $edocId;
        } finally {
            if (is_file($temporaryPath)) {
                @unlink($temporaryPath);
            }
        }
    }

    private function can_configure_project_settings($projectId)
    {
        if (!is_numeric($projectId) || (int) $projectId < 1) {
            return false;
        }
        try {
            $user = $this->getUser();
            return $user->isSuperUser() || $user->hasDesignRights((int) $projectId);
        } catch (Throwable $exception) {
            return false;
        }
    }

    private function require_project_settings_access($projectId)
    {
        if (!is_numeric($projectId) || (int) $projectId < 1) {
            throw new \InvalidArgumentException("Project ID must be a positive integer.");
        }
        $projectId = (int) $projectId;
        if (!$this->can_configure_project_settings($projectId)) {
            throw new \RuntimeException("Project design rights are required to configure Watermarked Signatures.");
        }
        return $projectId;
    }

    private function is_valid_background_image_mode($mode)
    {
        return is_string($mode) && in_array($mode, array(
            self::BACKGROUND_IMAGE_REDCAP,
            self::BACKGROUND_IMAGE_CUSTOM,
            self::BACKGROUND_IMAGE_NONE
        ), true);
    }

    private function is_valid_public_project_reference($reference)
    {
        return $reference === null
            || (is_string($reference)
                && strlen($reference) <= Renderer::MAX_PROJECT_REFERENCE_LENGTH
                && preg_match('/^[A-Za-z0-9][A-Za-z0-9 ._\/-]*$/D', $reference));
    }

    private function unbound_upload_retention_days($projectId)
    {
        $setting = $this->getProjectSetting('unbound-upload-retention-days', (int) $projectId);
        if ($setting === null || $setting === '') {
            return self::DEFAULT_UNBOUND_UPLOAD_RETENTION_DAYS;
        }

        $setting = (string) $setting;
        if (!ctype_digit($setting)) {
            return self::DEFAULT_UNBOUND_UPLOAD_RETENTION_DAYS;
        }

        return min((int) $setting, self::MAX_UNBOUND_UPLOAD_RETENTION_DAYS);
    }

    #endregion

}
