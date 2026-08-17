<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule;

#region Use and Require

use Exception;
use Throwable;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\Anchor;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\BindingMac;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\CanonicalJson;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\EnvelopeSigner;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\IpCipher;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\KeyDerivation;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
use DE\RUB\WatermarkedSignaturesExternalModule\Context\SavedContext;
use DE\RUB\WatermarkedSignaturesExternalModule\Econsent\IpService;
use DE\RUB\WatermarkedSignaturesExternalModule\Storage\LogRepository;
use DE\RUB\WatermarkedSignaturesExternalModule\Watermark\Renderer;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\AdministratorVerificationController;
use DE\RUB\WatermarkedSignaturesExternalModule\Verification\DatabaseQueryToolAccess;
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
require_once "classes/Crypto/IpCipher.php";
require_once "classes/Context/SavedContext.php";
require_once "classes/Econsent/IpService.php";
require_once "classes/Storage/LogRepository.php";
require_once "classes/Watermark/Renderer.php";
require_once "classes/Verification/AdministratorVerificationController.php";
require_once "classes/Verification/DatabaseQueryToolAccess.php";
require_once "classes/Verification/RedcapEdocReader.php";
require_once "classes/Verification/RedcapCurrentValueReader.php";
require_once "classes/Verification/RedcapFieldLink.php";
require_once "classes/Verification/VerificationService.php";
require_once "classes/Verification/ProjectAccessPolicy.php";
require_once "classes/Verification/ProjectVerificationController.php";

#endregion

class WatermarkedSignaturesExternalModule extends \ExternalModules\AbstractExternalModule
{
	/** @var bool Whether browser-side debug logging is enabled. */
	private $js_debug = false;

	/** @var \Project */
	private $proj = null;

	/** @var int|null Current REDCap project ID. */
	private $project_id = null;

	const ACTIONTAG = "@WATERMARKED-SIGNATURE";
	const ENVELOPE_VERSION = 1;
	// Version of the matched upload/binding provenance pair. This is distinct
	// from the visible WM1 watermark and signed-envelope format versions.
	const BINDING_PROVENANCE_VERSION = 3;
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
	const AJAX_VALIDATE_PROJECT_SETTINGS = "validate-project-settings";

    #region Hooks

	/**
	 * @param int $project_id
	 * @param string $record
	 * @param string $instrument
	 * @param int $event_id
	 * @param int|null $group_id
	 * @param int $repeat_instance
	 * @return void
	 */
	function redcap_data_entry_form($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
	{
		$this->init_proj($project_id);
		$this->init_config();
		$this->inject_capture_envelopes($instrument, $event_id, self::ORIGIN_DATA_ENTRY);
	}

	/**
	 * @param int $project_id
	 * @param string $record
	 * @param string $instrument
	 * @param int $event_id
	 * @param int|null $group_id
	 * @param string $survey_hash
	 * @param int $response_id
	 * @param int $repeat_instance
	 * @return void
	 */
	function redcap_survey_page($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
	{
		$this->init_proj($project_id);
		$this->init_config();
		$this->inject_capture_envelopes($instrument, $event_id, self::ORIGIN_SURVEY);
	}

	/**
	 * The signature receiver calls this hook before decoding myfile_base64.
	 *
	 * @param int|null $project_id
	 * @return void
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

	/**
	 * @param int|null $project_id
	 * @return void
	 */
	function redcap_every_page_top($project_id)
	{
		// Skip non-project context
		if ($project_id == null) return;

		// Initialize
		$this->init_proj($project_id);
		$this->init_config();
		$this->inject_online_designer_action_tag_audit((int) $project_id);
	}

	/**
	 * Add the action-tag audit to the Online Designer for project designers.
	 * With an instrument selected, the audit is deliberately limited to that
	 * instrument so it stays close to the fields being edited.
	 *
	 * @param int $projectId
	 * @return void
	 */
	private function inject_online_designer_action_tag_audit($projectId)
	{
		if (
			!defined('PAGE')
			|| PAGE !== 'Design/online_designer.php'
			|| !$this->can_configure_project_settings($projectId)
		) {
			return;
		}

		$instrument = isset($_GET['page']) && is_string($_GET['page']) && $_GET['page'] !== ''
			? $_GET['page']
			: null;
		$actionTagAudit = $this->project_action_tag_audit($instrument);
		if (empty($actionTagAudit)) {
			return;
		}

		$module = $this;
		$actionTagAuditFieldLinks = $instrument !== null;
		$actionTagAuditScope = $instrument === null ? 'project' : 'instrument';
		echo '<div id="sigwm-online-designer-action-tag-audit" hidden>';
		require __DIR__ . '/pages/partials/action-tag-audit.php';
		echo '</div>';
		InjectionHelper::init($this)->js('js/online-designer-action-tag-audit.js');
	}

	/**
	 * @param int $project_id
	 * @param string $record
	 * @param string $instrument
	 * @param int $event_id
	 * @param int|null $group_id
	 * @param string|null $survey_hash
	 * @param int|null $response_id
	 * @param int $repeat_instance
	 * @return void
	 */
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
	 *
	 * @param int|string|null $project_id
	 * @param array<string, mixed> $post
	 * @return null
	 */
	function redcap_module_api_before($project_id, $post)
	{
		if (
			!is_numeric($project_id) || (int) $project_id < 1 || !is_array($post)
			|| ($post['content'] ?? null) !== 'record' || ($post['action'] ?? null) !== 'rename'
		) {
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
	 *
	 * @param array<string, mixed> $cronAttributes
	 * @return void
	 */
	function cron_purge_unbound_upload_provenance($cronAttributes)
	{
		foreach ($this->getProjectsWithModuleEnabled() as $projectId) {
			$projectId = (int) $projectId;
			if ($projectId < 1) {
				continue;
			}

			try {
				$this->framework->setProjectId($projectId);
				$repository = new LogRepository($this, $this->binding_mac());
				// EM log timestamps are written with the database's current
				// application time; use REDCap/PHP's configured local time
				// rather than serializing this cutoff as UTC.
				$nonceCutoff = date(
					'Y-m-d H:i:s',
					time() - self::ENVELOPE_MAX_TTL_SECONDS - self::CLOCK_SKEW_SECONDS
				);
				$repository->purgeExpiredEnvelopeNonces($nonceCutoff);

				$retentionDays = $this->unbound_upload_retention_days($projectId);
				if ($retentionDays > 0) {
					$cutoff = date('Y-m-d H:i:s', time() - ($retentionDays * 86400));
					$repository->purgeExpiredUnboundUploads($cutoff);
				}
			} catch (Throwable $exception) {
				error_log('Watermarked Signatures retention cleanup failed for project ' . $projectId . ': ' . $exception->getMessage());
			}
		}
	}

	/**
	 * @param int|string|null $project_id
	 * @param array<string, mixed> $link
	 * @return array<string, mixed>|null
	 */
	function redcap_module_link_check_display($project_id, $link)
	{
		$linkKey = $link["key"] ?? "";
		if ($linkKey === "administrator-signature-verification") {
			return $this->can_access_control_center_verification() ? $link : null;
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
	 * @param string $action
	 * @param mixed $payload
	 * @param int|string|null $project_id
	 * @param string|null $record
	 * @param string|null $instrument
	 * @param int|string|null $event_id
	 * @param int|string|null $repeat_instance
	 * @param string|null $survey_hash
	 * @param int|string|null $response_id
	 * @param string|null $survey_queue_hash
	 * @param string|null $page
	 * @param string|null $page_full
	 * @param int|string|null $user_id
	 * @param int|string|null $group_id
	 * @return array{ok: bool, errors: array<string, string>}|null
	 */
	function redcap_module_ajax($action, $payload, $project_id, $record, $instrument, $event_id, $repeat_instance, $survey_hash, $response_id, $survey_queue_hash, $page, $page_full, $user_id, $group_id)
	{
		if ($action !== self::AJAX_VALIDATE_PROJECT_SETTINGS) {
			return null;
		}
		if (!is_array($payload)) {
			return array(
				"ok" => false,
				"errors" => array("form" => "settings_error_invalid_request")
			);
		}

		try {
			return $this->validate_project_settings_input(
				$project_id,
				$payload,
				!empty($payload["has_pending_custom_image"])
			);
		} catch (Throwable $exception) {
			return array(
				"ok" => false,
				"errors" => array("form" => "settings_error_validation_unavailable")
			);
		}
	}

	/**
	 * @param int|string $projectId
	 * @return array{retention_days:int,public_project_reference:string,background_image_mode:string,background_image_rotation:int,action_tag_audit:array<int, array{field:string,instrument:string,code:string,reference_value:?string,reference_length:?int,maximum_length:?int,diagnostics:array<int,array{code:string,positions:array<int,int>,maximum_length:?int}>}>,custom_image:array{available:bool,edoc_id:string,doc_name:?string,width:?int,height:?int,sha256:?string,preview_data_url:?string}}
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
			"action_tag_audit" => $this->project_action_tag_audit(),
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
	 * Inspect every Watermarked Signatures action tag in the current project.
	 * This intentionally reports tags on unsupported fields as well as tags on
	 * signature fields, so a project-wide audit cannot silently skip a typo.
	 *
	 * @param int|string $projectId
	 * @return array<int, array{field:string,instrument:string,code:string,reference_value:?string,reference_length:?int,maximum_length:?int,diagnostics:array<int,array{code:string,positions:array<int,int>,maximum_length:?int}>}>
	 */
	public function get_project_action_tag_audit($projectId)
	{
		if (!is_numeric($projectId) || (int) $projectId < 1) {
			throw new \InvalidArgumentException('Project ID must be a positive integer.');
		}
		$this->init_proj((int) $projectId);
		$this->init_config();

		return $this->project_action_tag_audit();
	}

	/**
	 * Validate the settings that can be sent through the framework AJAX API.
	 * File bytes are validated and normalized only by the ordinary form save.
	 *
	 * @param int|string $projectId
	 * @param array<string,mixed> $input
	 * @param bool $hasPendingCustomImage
	 * @return array{ok:bool,errors:array<string,string>}
	 */
	public function validate_project_settings_input($projectId, $input, $hasPendingCustomImage = false)
	{
		$projectId = $this->require_project_settings_access($projectId);
		$this->init_proj($projectId);
		$this->init_config();

		$errors = $this->project_settings_validation_errors(
			$input,
			$hasPendingCustomImage && !$this->remove_custom_background_image_requested($input),
			$this->remove_custom_background_image_requested($input)
		);
		return array(
			"ok" => empty($errors),
			"errors" => $errors
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
			$hasPendingCustomImage = $this->has_pending_custom_background_image($uploadedFile);
			// An explicit removal wins over a file selected earlier in the same form.
			$removeCustomImage = $this->remove_custom_background_image_requested($input);
			$validationErrors = $this->project_settings_validation_errors(
				$input,
				$hasPendingCustomImage && !$removeCustomImage,
				$removeCustomImage
			);
			if (!empty($validationErrors)) {
				throw new \InvalidArgumentException(reset($validationErrors));
			}
			$retentionDays = $this->validate_unbound_upload_retention_days($input["retention_days"] ?? null);
			$projectReference = $this->validate_project_settings_public_reference($input["public_project_reference"] ?? null);
			$backgroundMode = (string) $input["background_image_mode"];
			$backgroundRotation = $this->validate_background_image_rotation($input["background_image_rotation"] ?? null);
			$normalizedImage = $removeCustomImage
				? null
				: $this->normalized_uploaded_custom_background_image($uploadedFile);

			$newEdocId = $normalizedImage === null
				? null
				: $this->store_normalized_custom_background_image(
					$normalizedImage,
					$this->custom_background_image_upload_name($uploadedFile),
					$projectId
				);
			$this->framework->setProjectSetting("unbound-upload-retention-days", (string) $retentionDays, $projectId);
			$this->framework->setProjectSetting("public-project-reference", $projectReference, $projectId);
			$this->framework->setProjectSetting("background-image-mode", $backgroundMode, $projectId);
			$this->framework->setProjectSetting("background-image-rotation", (string) $backgroundRotation, $projectId);
			if ($newEdocId !== null) {
				$this->framework->setProjectSetting("custom-background-image", (string) $newEdocId, $projectId);
			} elseif ($removeCustomImage) {
				$this->framework->removeProjectSetting("custom-background-image", $projectId);
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

	/**
	 * @param int|string $projectId
	 * @return ProjectVerificationController
	 */
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

		$bindingMac = $this->binding_mac();
		$repository = new LogRepository($this, $bindingMac);
		$service = new VerificationService(
			$repository,
			$bindingMac,
			new RedcapEdocReader(),
			new RedcapCurrentValueReader()
		);
		return new ProjectVerificationController(
			$projectId,
			$repository,
			$bindingMac,
			$service,
			$policy,
			$this->econsent_ip_service()
		);
	}

	/**
	 * @return AdministratorVerificationController
	 */
	public function get_administrator_verification_controller()
	{
		if (!$this->can_access_control_center_verification()) {
			throw new \RuntimeException("Administrator access is required for global signature verification.");
		}

		$bindingMac = $this->binding_mac();
		$repository = new LogRepository($this, $bindingMac);
		$service = new VerificationService(
			$repository,
			$bindingMac,
			new RedcapEdocReader(),
			new RedcapCurrentValueReader()
		);
		return new AdministratorVerificationController(
			$repository,
			$service,
			$this->econsent_ip_service(),
			DatabaseQueryToolAccess::canAccessDatabaseQueryTool()
		);
	}

    #endregion



    #region Private Helpers

	/**
	 * Determines whether the current user should be allowed to access the control center verification page
	 * @return bool
	 */
	private function can_access_control_center_verification()
	{
		return (defined('ACCESS_ADMIN_DASHBOARDS') && ACCESS_ADMIN_DASHBOARDS == 1);
	}

	/**
	 * Build the version-aware binding MAC helper. The base key intentionally
	 * remains the v1 key so released v1.0.2 code can verify format-v2 bindings.
	 *
	 * @return BindingMac
	 */
	private function binding_mac()
	{
		return new BindingMac(
			KeyDerivation::derive(KeyDerivation::BINDING_INFO),
			KeyDerivation::derive(KeyDerivation::BINDING_EXTENSION_INFO),
			KeyDerivation::derive(KeyDerivation::ECONSENT_IP_BINDING_INFO)
		);
	}

	/** @return IpService */
	private function econsent_ip_service()
	{
		return new IpService(new IpCipher(
			KeyDerivation::derive(KeyDerivation::ECONSENT_IP_ENCRYPTION_INFO)
		));
	}

	/**
	 * @param string $record
	 * @param string $instrument
	 * @param int $eventId
	 * @param int $repeatInstance
	 * @param 'data_entry'|'survey' $saveOrigin
	 * @param string|null $saveUsername
	 * @return void
	 */
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
		$bindingMac = $this->binding_mac();
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
						"v" => (int) ($upload['v'] ?? 1),
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
				if (array_key_exists('field_reference', $upload)) {
					$binding['field_reference'] = $upload['field_reference'];
				}
				if ((int) ($upload['v'] ?? 1) >= 3) {
					foreach (array(
						'econsent_survey_id',
						'econsent_ip_system_setting_enabled',
						'econsent_ip_capture_status',
						'econsent_signature_ip_ciphertext',
						'data_entry_signature_ip_capture_status',
						'data_entry_signature_ip_ciphertext'
					) as $ipCaptureField) {
						$binding[$ipCaptureField] = $upload[$ipCaptureField];
					}
				}
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

	/**
	 * @param array<string, mixed> $upload
	 * @param SavedContext $savedContext
	 * @param string $field
	 * @param int $edocId
	 * @return void
	 */
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
		if (
			!array_key_exists("capture_username", $upload)
			|| ($upload["capture_username"] !== null && !is_string($upload["capture_username"]))
		) {
			throw new \UnexpectedValueException("Upload provenance contains an invalid capture username.");
		}
		if (
			!array_key_exists("project_reference", $upload)
			|| !$this->is_valid_public_project_reference($upload["project_reference"])
		) {
			throw new \UnexpectedValueException("Upload provenance contains an invalid public project reference.");
		}
		if (
			array_key_exists('field_reference', $upload)
			&& !$this->is_valid_field_reference($upload['field_reference'])
		) {
			throw new \UnexpectedValueException('Upload provenance contains an invalid field reference.');
		}
		if ((int) ($upload['v'] ?? 1) >= 3 && !IpService::isValidCaptureContext($upload)) {
			throw new \UnexpectedValueException('Upload provenance contains invalid e-Consent IP capture context.');
		}
		if ((int) ($upload['v'] ?? 1) >= 3
			&& !IpService::isValidDataEntryCaptureContext($upload, $upload['capture_origin'])) {
			throw new \UnexpectedValueException('Upload provenance contains invalid data-entry IP capture context.');
		}
		if (
			array_key_exists("background_image_mode", $upload)
			&& !$this->is_valid_background_image_mode($upload["background_image_mode"])
		) {
			throw new \UnexpectedValueException("Upload provenance contains an invalid selected background image mode.");
		}
		if (
			array_key_exists("background_image_effective_mode", $upload)
			&& !$this->is_valid_background_image_mode($upload["background_image_effective_mode"])
		) {
			throw new \UnexpectedValueException("Upload provenance contains an invalid applied background image mode.");
		}
		if (
			array_key_exists("background_image_sha256", $upload)
			&& $upload["background_image_sha256"] !== null
			&& (!is_string($upload["background_image_sha256"])
				|| !preg_match('/^[a-f0-9]{64}$/', $upload["background_image_sha256"]))
		) {
			throw new \UnexpectedValueException("Upload provenance contains an invalid background image digest.");
		}
		if (
			array_key_exists("background_image_rotation", $upload)
			&& !$this->is_valid_background_image_rotation($upload["background_image_rotation"])
		) {
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

	/**
	 * @param string $eventType
	 * @param string $record
	 * @param string $field
	 * @param scalar|null $edocId
	 * @param string $message
	 * @return void
	 */
	private function log_binding_error($eventType, $record, $field, $edocId, $message)
	{
		$this->safe_log_event($eventType, array(
			"record" => (string) $record,
			"field" => (string) $field,
			"edoc_id" => is_scalar($edocId) ? (string) $edocId : "",
			"technical_message" => substr((string) $message, 0, 1000)
		));
	}

	/**
	 * @param string $eventType
	 * @param array<string, mixed> $parameters
	 * @return int|string|null REDCap log ID when written, otherwise null.
	 */
	private function safe_log_event($eventType, $parameters)
	{
		// Public-survey requests are client-triggered and may be repeated
		// without a REDCap user session. Keep their durable log footprint to
		// the successful provenance event and the one-time replay guard.
		if (\ExternalModules\ExternalModules::isNoAuth()) {
			return null;
		}

		try {
			return $this->log($eventType, $parameters);
		} catch (Throwable $exception) {
			error_log("Watermarked Signatures logging failed ({$eventType}): " . $exception->getMessage());
			return null;
		}
	}

	/** @return string UTC ISO 8601 timestamp with milliseconds. */
	private function utc_now()
	{
		$now = new \DateTimeImmutable("now", new \DateTimeZone("UTC"));
		return $now->format("Y-m-d\\TH:i:s.v\\Z");
	}

	/** @return string|null Current REDCap username, if authenticated. */
	private function current_username()
	{
		$username = null;
		if (
			class_exists("\\ExternalModules\\ExternalModules")
			&& method_exists("\\ExternalModules\\ExternalModules", "getUsername")
		) {
			$username = \ExternalModules\ExternalModules::getUsername();
		} elseif (defined("USERID")) {
			$username = USERID;
		}

		return $username === null || $username === "" ? null : (string) $username;
	}

	/**
	 * @param string $record
	 * @param 'data_entry'|'survey' $saveOrigin
	 * @param string|null $saveUsername
	 * @return void
	 */
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

		$repository = new LogRepository($this, $this->binding_mac());
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
	 *
	 * @return void
	 */
	private function capture_direct_record_rename()
	{
		if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
			|| ($_GET['route'] ?? '') !== 'DataEntryController:renameRecord'
		) {
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
	 *
	 * @param string $requestedOldRecord
	 * @param string $requestedNewRecord
	 * @param string $renameOrigin
	 * @return void
	 */
	private function capture_record_rename_response($requestedOldRecord, $requestedNewRecord, $renameOrigin)
	{
		try {
			$repository = new LogRepository($this, $this->binding_mac());
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
					$repository = new LogRepository($module, $module->binding_mac());
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

	/**
	 * @param string $key
	 * @return string|null
	 */
	private function posted_record_name($key)
	{
		return $this->record_name_from_values($_POST, $key);
	}

	/**
	 * @param array<string, mixed> $values
	 * @param string $key
	 * @return string|null
	 */
	private function record_name_from_values($values, $key)
	{
		if (!is_array($values) || !isset($values[$key]) || !is_scalar($values[$key])) {
			return null;
		}
		$record = trim((string) $values[$key]);
		return $record === '' ? null : $record;
	}

	/**
	 * @param LogRepository $repository
	 * @param string $oldRecord
	 * @param string $newRecord
	 * @param string $renameOrigin
	 * @param string|null $renameUsername
	 * @return void
	 */
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

	/**
	 * @param mixed $origin
	 * @return bool
	 */
	private function is_valid_origin($origin)
	{
		return $origin === self::ORIGIN_DATA_ENTRY || $origin === self::ORIGIN_SURVEY;
	}

	/**
	 * @param string $instrument
	 * @param int $event_id
	 * @param 'data_entry'|'survey' $captureOrigin
	 * @return void
	 */
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
		$projectReference = $this->public_project_reference();
		$metadata = $this->get_project_metadata();

		foreach ($fields as $field) {
			$fieldConfiguration = $this->signature_field_configuration($metadata[$field]);
			$fieldReference = $fieldConfiguration['field_reference'];
			$fieldReferenceError = $fieldConfiguration['field_reference_error'];
			$fieldReferenceErrorValue = $fieldConfiguration['field_reference_error_value'];
			$fieldReferenceErrorLength = $fieldConfiguration['field_reference_error_length'];
			$fieldReferenceDiagnostics = $fieldConfiguration['field_reference_diagnostics'];
			if (
				$fieldReference !== null
				&& $projectReference !== null
				&& strlen($projectReference) > Renderer::MAX_PROJECT_REFERENCE_LENGTH
			) {
				$fieldReference = null;
				$fieldReferenceError = 'project_reference_too_long';
				$fieldReferenceErrorValue = $projectReference;
				$fieldReferenceErrorLength = $this->reference_character_length($projectReference);
				$fieldReferenceDiagnostics = $this->reference_length_diagnostics(
					$projectReference,
					Renderer::MAX_PROJECT_REFERENCE_LENGTH
				);
			}
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
				"project_reference" => $projectReference,
				"field_reference" => $fieldReference,
				"field_reference_error" => $fieldReferenceError,
				"field_reference_error_value" => $fieldReferenceErrorValue,
				"field_reference_error_length" => $fieldReferenceErrorLength,
				"field_reference_diagnostics" => $fieldReferenceDiagnostics,
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

	/** @return void */
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

		if (\ExternalModules\ExternalModules::isNoAuth()) {
			try {
				$repository = new LogRepository($this, $this->binding_mac());
				if (!$repository->reserveEnvelopeNonce($payload['nonce'])) {
					throw new \UnexpectedValueException('The signed signature envelope has already been used.');
				}
			} catch (Throwable $exception) {
				// Fail closed. fail_upload() deliberately does not persist a
				// no-auth error row, so nonce replay attempts cannot amplify
				// the module log.
				$this->fail_upload($field, 'sigwm_error_replayed_envelope', $exception->getMessage());
				return;
			}
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
		$econsentIpContext = $this->econsent_ip_service()->capture(
			$this->proj,
			$payload['pid'],
			$payload['event_id'],
			$payload['instrument'],
			$payload['field'],
			$payload['capture_origin'],
			$captureReference
		);

		try {
			$backgroundImage = $this->background_image_profile();
			$fieldReference = $payload['field_reference'] ?? null;
			$this->log_field_reference_configuration_error($payload, $fieldReference);
			$renderer = new Renderer();
			$watermarkedPng = $renderer->renderBase64(
				isset($_POST["myfile_base64"]) ? $_POST["myfile_base64"] : "",
				$anchor,
				$payload["context_ref"],
				$captureReference,
				$capturedAt,
				$this->visible_reference($payload["project_reference"], $fieldReference),
				$backgroundImage
			);
		} catch (Throwable $exception) {
			$this->fail_upload($field, "sigwm_error_upload_render", $exception->getMessage());
			return;
		}

		$_POST["myfile_base64"] = base64_encode($watermarkedPng);
		$provenance = array(
			"v" => self::BINDING_PROVENANCE_VERSION,
			"capture_ref" => $captureReference,
			"context_ref" => $payload["context_ref"],
			"record_ref" => isset($payload["record_ref"]) ? $payload["record_ref"] : null,
			"project_reference" => $payload["project_reference"],
			"field_reference" => $fieldReference,
			"field_reference_error" => $payload['field_reference_error'] ?? null,
			"field_reference_error_value" => $payload['field_reference_error_value'] ?? null,
			"field_reference_error_length" => $payload['field_reference_error_length'] ?? null,
			"field_reference_diagnostics" => $payload['field_reference_diagnostics'] ?? array(),
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
		$provenance = array_merge($provenance, $econsentIpContext);

		$this->capture_edoc_id_from_response($field, $provenance);
	}

	/**
	 * @param array<string, mixed> $payload
	 * @param string $postedField
	 * @param array<string, mixed> $fieldMetadata
	 * @return void
	 */
	private function validate_envelope_payload($payload, $postedField, $fieldMetadata)
	{
		$required = array(
			"v",
			"pid",
			"event_id",
			"instrument",
			"field",
			"context_ref",
			"record_ref",
			"project_reference",
			"capture_origin",
			"issued_at",
			"expires_at",
			"nonce",
			"purpose"
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
		if (
			$payload["record_ref"] !== null
			&& (!is_string($payload["record_ref"]) || !preg_match('/^R-[0-9A-HJKMNP-TV-Z-]+$/', $payload["record_ref"]))
		) {
			throw new \UnexpectedValueException("Invalid envelope record reference.");
		}
		if (!$this->is_valid_public_project_reference($payload["project_reference"])) {
			throw new \UnexpectedValueException("Invalid envelope public project reference.");
		}
		if (array_key_exists('field_reference', $payload) && !$this->is_valid_field_reference($payload['field_reference'])) {
			throw new \UnexpectedValueException('Invalid envelope field reference.');
		}
		if (
			($payload['field_reference'] ?? null) !== null
			&& $payload['project_reference'] !== null
			&& strlen($payload['project_reference']) > Renderer::MAX_PROJECT_REFERENCE_LENGTH
		) {
			throw new \UnexpectedValueException('A legacy public project reference cannot be combined with a field reference.');
		}
		if (
			array_key_exists('field_reference_error', $payload)
			&& !$this->is_valid_field_reference_error($payload['field_reference_error'])
		) {
			throw new \UnexpectedValueException('Invalid envelope field reference configuration error.');
		}
		if (
			array_key_exists('field_reference_error_value', $payload)
			&& !$this->is_valid_field_reference_error_value($payload['field_reference_error_value'])
		) {
			throw new \UnexpectedValueException('Invalid envelope field reference configuration value.');
		}
		if (
			array_key_exists('field_reference_error_length', $payload)
			&& !$this->is_valid_field_reference_error_length($payload['field_reference_error_length'])
		) {
			throw new \UnexpectedValueException('Invalid envelope field reference configuration length.');
		}
		if (
			array_key_exists('field_reference_diagnostics', $payload)
			&& !$this->is_valid_field_reference_diagnostics($payload['field_reference_diagnostics'])
		) {
			throw new \UnexpectedValueException('Invalid envelope field reference configuration diagnostics.');
		}
		if (
			($payload['field_reference_error'] ?? null) !== null
			&& ($payload['field_reference'] ?? null) !== null
		) {
			throw new \UnexpectedValueException('An envelope cannot contain both a field reference and a field reference configuration error.');
		}
		if (
			($payload['field_reference_error'] ?? null) === null
			&& (
				($payload['field_reference_error_value'] ?? null) !== null
				|| ($payload['field_reference_error_length'] ?? null) !== null
				|| !empty($payload['field_reference_diagnostics'])
			)
		) {
			throw new \UnexpectedValueException('An envelope cannot contain field reference diagnostics without a configuration error.');
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

	/**
	 * @param string $field
	 * @param array<string, mixed> $provenance
	 * @return void
	 */
	private function capture_edoc_id_from_response($field, $provenance)
	{
		$module = $this;
		$recorded = false;
		$responseFailureLogged = false;
		$fieldPattern = preg_quote($field, '/');

		ob_start(function ($output) use ($module, &$recorded, &$responseFailureLogged, $fieldPattern, $provenance) {
			if (!$recorded && preg_match(
				"/stopUpload\\(\\s*1\\s*,\\s*(['\"]){$fieldPattern}\\1\\s*,\\s*(['\"])([1-9][0-9]*)\\2/",
				$output,
				$matches
			)) {
				$recorded = true;
				$event = $provenance;
				$event["edoc_id"] = (int) $matches[3];
				$module->append_upload_provenance($event);
			} elseif (
				!$recorded && !$responseFailureLogged
				&& preg_match('/stopUpload\\(\\s*1\\b/', $output)
			) {
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

	/**
	 * Append the immutable provenance event after a watermark upload succeeds.
	 *
	 * @param array<string, mixed> $event
	 * @return bool Whether the provenance event was written.
	 */
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
	 *
	 * @param string $eventType
	 * @param array<string, mixed> $provenance
	 * @param string $technicalMessage
	 * @return void
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

	/**
	 * @param string $field
	 * @param string $eventType
	 * @param string $technicalMessage
	 * @return void Does not return after exitAfterHook().
	 */
	private function fail_upload($field, $eventType, $technicalMessage)
	{
		// A public survey respondent can repeatedly submit an invalid upload.
		// Fail closed, but do not turn those requests into unbounded durable
		// module-log entries. Successful survey uploads remain logged later,
		// once REDCap has assigned their edoc ID.
		if (!\ExternalModules\ExternalModules::isNoAuth()) {
			try {
				$this->log($eventType, array(
					"field" => $field,
					"event_id" => isset($_GET["event_id"]) && is_numeric($_GET["event_id"]) ? (int) $_GET["event_id"] : "",
					"technical_message" => substr((string) $technicalMessage, 0, 1000)
				));
			} catch (Throwable $exception) {
				error_log("Watermarked Signatures error logging failed: " . $exception->getMessage());
			}
		}

		$message = $this->framework->tt('ui_upload_watermark_failed'); // The signature could not be securely watermarked. Refresh the form or survey page, then capture the signature again.
		$fieldJson = json_encode(
			$this->escape($field),
			JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
		);
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

	/** @return bool */
	private function is_signature_upload_request()
	{
		$page = defined("PAGE") ? (string) PAGE : "";
		$passthru = isset($_GET["__passthru"]) ? rawurldecode((string) $_GET["__passthru"]) : "";

		return $page === "DataEntry/file_upload.php"
			|| substr($page, -strlen("/DataEntry/file_upload.php")) === "/DataEntry/file_upload.php"
			|| $passthru === "DataEntry/file_upload.php";
	}

	/** @return string|null */
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

	/**
	 * @param string $instrument
	 * @return array<int, string>
	 */
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

	/** @return array<int, string> */
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

	/**
	 * @param int $projectId
	 * @return ProjectAccessPolicy
	 */
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

	/**
	 * @param array<string, mixed> $metadata
	 * @return bool
	 */
	private function is_configured_signature_field($metadata)
	{
		if (!$this->is_signature_field_metadata($metadata)) {
			return false;
		}

		return $this->signature_field_configuration($metadata)['configured'];
	}

	/**
	 * @param array<string, mixed> $metadata
	 * @return array{configured:bool,field_reference:?string,field_reference_error:?string,field_reference_error_value:?string,field_reference_error_length:?int,field_reference_diagnostics:array<int,array{code:string,positions:array<int,int>,maximum_length:?int}>}
	 */
	private function signature_field_configuration($metadata)
	{
		$annotation = isset($metadata['misc']) ? $metadata['misc'] : ($metadata['field_annotation'] ?? '');
		$annotation = (string) $annotation;
		$tags = ActionTagHelper::parseActionTags($annotation, self::ACTIONTAG);
		if (!is_array($tags) || count($tags) === 0) {
			return $this->field_reference_configuration(false);
		}
		if (count($tags) !== 1) {
			return $this->field_reference_configuration(true, null, 'multiple_action_tags');
		}

		$tag = $tags[0];
		$rawMatch = trim((string) ($tag['match'] ?? ''));
		if (preg_match('/@WATERMARKED-SIGNATURE\s*=/i', $annotation) && strpos($rawMatch, '=') === false) {
			return $this->field_reference_configuration(true, null, 'field_reference_parameter_format');
		}
		if (($tag['params'] ?? '') === '') {
			return $this->field_reference_configuration(true);
		}
		if (!preg_match('/^@WATERMARKED-SIGNATURE="([^"]*)"$/iD', $rawMatch, $matches)) {
			return $this->field_reference_configuration(true, null, 'field_reference_parameter_format');
		}

		$fieldReferenceAnalysis = $this->field_reference_value_analysis($matches[1]);
		if (!empty($fieldReferenceAnalysis['diagnostics'])) {
			return $this->field_reference_configuration(
				true,
				null,
				$fieldReferenceAnalysis['diagnostics'][0]['code'],
				$fieldReferenceAnalysis['raw_value'],
				$fieldReferenceAnalysis['reference_length'],
				$fieldReferenceAnalysis['diagnostics']
			);
		}
		return $this->field_reference_configuration(true, $fieldReferenceAnalysis['reference_value']);
	}

	/**
	 * @param bool $configured
	 * @param string|null $fieldReference
	 * @param string|null $error
	 * @param string|null $errorValue
	 * @param int|null $errorLength
	 * @param array<int,array{code:string,positions:array<int,int>,maximum_length:?int}> $diagnostics
	 * @return array{configured:bool,field_reference:?string,field_reference_error:?string,field_reference_error_value:?string,field_reference_error_length:?int,field_reference_diagnostics:array<int,array{code:string,positions:array<int,int>,maximum_length:?int}>}
	 */
	private function field_reference_configuration($configured, $fieldReference = null, $error = null, $errorValue = null, $errorLength = null, $diagnostics = array())
	{
		return array(
			'configured' => (bool) $configured,
			'field_reference' => $fieldReference,
			'field_reference_error' => $error,
			'field_reference_error_value' => $errorValue,
			'field_reference_error_length' => $errorLength,
			'field_reference_diagnostics' => $diagnostics
		);
	}

	/**
	 * @param string|null $instrument Restrict the audit to one Online Designer instrument when provided.
	 * @return array<int, array{field:string,instrument:string,code:string,reference_value:?string,reference_length:?int,maximum_length:?int,diagnostics:array<int,array{code:string,positions:array<int,int>,maximum_length:?int}>}>
	 */
	private function project_action_tag_audit($instrument = null)
	{
		$issues = array();
		$projectReference = $this->public_project_reference();
		foreach ($this->get_project_metadata() as $field => $metadata) {
			if ($instrument !== null && ($metadata['form_name'] ?? null) !== $instrument) {
				continue;
			}
			$fieldConfiguration = $this->signature_field_configuration($metadata);
			if (!$fieldConfiguration['configured']) {
				continue;
			}

			$issue = array(
				'field' => (string) $field,
				'instrument' => (string) ($metadata['form_name'] ?? ''),
				'code' => '',
				'reference_value' => null,
				'reference_length' => null,
				'maximum_length' => null,
				'diagnostics' => array()
			);
			if (!$this->is_signature_field_metadata($metadata)) {
				$issue['code'] = 'action_tag_unsupported_field';
				$issues[] = $issue;
				continue;
			}
			if ($fieldConfiguration['field_reference_error'] !== null) {
				$issue['code'] = $fieldConfiguration['field_reference_error'];
				$issue['reference_value'] = $fieldConfiguration['field_reference_error_value'];
				$issue['reference_length'] = $fieldConfiguration['field_reference_error_length'];
				$issue['maximum_length'] = $this->field_reference_error_maximum_length($issue['code']);
				$issue['diagnostics'] = $fieldConfiguration['field_reference_diagnostics'];
				$issues[] = $issue;
				continue;
			}
			if (
				$fieldConfiguration['field_reference'] !== null
				&& $projectReference !== null
				&& strlen($projectReference) > Renderer::MAX_PROJECT_REFERENCE_LENGTH
			) {
				$issue['code'] = 'project_reference_too_long';
				$issue['reference_value'] = $projectReference;
				$issue['reference_length'] = $this->reference_character_length($projectReference);
				$issue['maximum_length'] = Renderer::MAX_PROJECT_REFERENCE_LENGTH;
				$issue['diagnostics'] = $this->reference_length_diagnostics(
					$projectReference,
					Renderer::MAX_PROJECT_REFERENCE_LENGTH
				);
				$issues[] = $issue;
			}
		}
		return $issues;
	}

	/**
	 * @param array<string, mixed> $metadata
	 * @return bool
	 */
	private function is_signature_field_metadata($metadata)
	{
		return ($metadata['element_type'] ?? null) === 'file'
			&& in_array($metadata['element_validation_type'] ?? null, array('signature', 'enhanced_signature'), true);
	}

	/** @return array<string, array<string, mixed>> */
	private function get_project_metadata()
	{
		if (class_exists("\\Design") && \Design::isDraftPreview() && !empty($this->proj->metadata_temp)) {
			return $this->proj->metadata_temp;
		}
		return $this->proj->metadata;
	}

	/**
	 * @param int $project_id
	 * @return void
	 */
	private function init_proj($project_id)
	{
		if ($this->proj == null) {
			$this->proj = new \Project($project_id);
			$this->project_id = $project_id;
		}
	}

	/** @return void */
	private function require_proj()
	{
		if ($this->proj == null) {
			throw new Exception($this->framework->tt('error_project_not_initialized')); // Project is not initialized.
		}
	}

	/** @return void */
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
	 *
	 * @return string|null
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
	 * @param string|null $projectReference
	 * @param string|null $fieldReference
	 * @return string|null
	 */
	private function visible_reference($projectReference, $fieldReference)
	{
		if (!$this->is_valid_public_project_reference($projectReference) || !$this->is_valid_field_reference($fieldReference)) {
			throw new \UnexpectedValueException('The visible watermark reference is invalid.');
		}
		if ($fieldReference === null) {
			return $projectReference;
		}
		if ($projectReference === null) {
			return $fieldReference;
		}
		if (strlen($projectReference) > Renderer::MAX_PROJECT_REFERENCE_LENGTH) {
			throw new \UnexpectedValueException('A legacy public project reference is too long to combine with a field reference.');
		}
		return $projectReference . ':' . $fieldReference;
	}

	/**
	 * @param array<string, mixed> $payload
	 * @param string|null $fieldReference
	 * @return void
	 */
	private function log_field_reference_configuration_error($payload, $fieldReference)
	{
		$error = $payload['field_reference_error'] ?? null;
		if ($error === null || $fieldReference !== null) {
			return;
		}
		$messages = array(
			'invalid_action_tag_parameter' => 'The @WATERMARKED-SIGNATURE parameter was invalid and was omitted from REF.',
			'field_reference_parameter_format' => 'The @WATERMARKED-SIGNATURE parameter must be a simple double-quoted string; the field reference was omitted from REF.',
			'field_reference_empty' => 'The configured field reference is empty; the field reference was omitted from REF.',
			'field_reference_too_long' => 'The configured field reference exceeds the 16-character limit; the field reference was omitted from REF.',
			'field_reference_invalid_start' => 'The configured field reference does not begin with an ASCII letter or digit; the field reference was omitted from REF.',
			'field_reference_invalid_characters' => 'The configured field reference contains unsupported characters; the field reference was omitted from REF.',
			'multiple_action_tags' => 'Multiple @WATERMARKED-SIGNATURE tags were configured for one field; the field reference was omitted from REF.',
			'project_reference_too_long' => 'The public project reference exceeds the 20-character limit for a combined REF value; the field reference was omitted from REF.'
		);
		$maximumLength = $this->field_reference_error_maximum_length($error);
		$diagnostics = $payload['field_reference_diagnostics'] ?? array();
		if (empty($diagnostics)) {
			$diagnostics = array($this->field_reference_diagnostic($error, array(), $maximumLength));
		}
		$diagnosticsJson = json_encode($diagnostics, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
		$this->safe_log_event('sigwm_error_field_reference', array(
			'event_id' => $payload['event_id'] ?? '',
			'instrument' => $payload['instrument'] ?? '',
			'field' => $payload['field'] ?? '',
			'field_reference_error' => $error,
			'field_reference_value' => $payload['field_reference_error_value'] ?? null,
			'field_reference_length' => $payload['field_reference_error_length'] ?? null,
			'field_reference_maximum_length' => $maximumLength,
			'field_reference_diagnostics' => $diagnosticsJson === false ? '[]' : $diagnosticsJson,
			'technical_message' => $messages[$error] ?? 'The field reference was omitted from REF.'
		));
	}

	/**
	 * Resolve the project-owned asset immediately before rendering. The stored
	 * digest describes the exact file used even when an administrator later
	 * replaces the retained setting.
	 *
	 * @return array{mode: 'redcap'|'custom'|'none', requested_mode: 'redcap'|'custom'|'none', contents: string|null, sha256: string|null, rotation: int}
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

	/**
	 * @return array{available: bool, edoc_id: string, doc_name: string|null, width: int|null, height: int|null, contents: string|null, technical_message: string|null}
	 */
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

	/** @return 'redcap'|'custom'|'none' */
	private function background_image_mode()
	{
		$mode = $this->getProjectSetting("background-image-mode");
		return $this->is_valid_background_image_mode($mode)
			? $mode
			: self::BACKGROUND_IMAGE_REDCAP;
	}

	/** @return int */
	private function background_image_rotation()
	{
		$rotation = $this->getProjectSetting("background-image-rotation");
		return $this->is_valid_background_image_rotation($rotation)
			? (int) $rotation
			: self::DEFAULT_BACKGROUND_IMAGE_ROTATION;
	}

	/**
	 * @param mixed $rotation
	 * @return bool
	 */
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

	/**
	 * @param mixed $value
	 * @return int
	 */
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

	/**
	 * @param mixed $value
	 * @return string
	 */
	private function validate_project_settings_public_reference($value)
	{
		if (!is_string($value)) {
			throw new \InvalidArgumentException("settings_error_public_project_reference");
		}
		$reference = trim($value);
		if ($reference !== "" && !$this->is_valid_new_public_project_reference($reference)) {
			throw new \InvalidArgumentException("settings_error_public_project_reference");
		}
		return $reference;
	}

	/**
	 * @param mixed $value
	 * @return int
	 */
	private function validate_background_image_rotation($value)
	{
		if (!$this->is_valid_background_image_rotation($value)) {
			throw new \InvalidArgumentException("settings_error_background_rotation");
		}
		return (int) $value;
	}

	/**
	 * @param array<string,mixed>|mixed $input
	 * @param bool $hasPendingCustomImage
	 * @param bool $removeCustomImage
	 * @return array<string,string>
	 */
	private function project_settings_validation_errors($input, $hasPendingCustomImage, $removeCustomImage = false)
	{
		if (!is_array($input)) {
			return array("form" => "settings_error_invalid_request");
		}

		$errors = array();
		try {
			$this->validate_unbound_upload_retention_days($input["retention_days"] ?? null);
		} catch (\InvalidArgumentException $exception) {
			$errors["retention_days"] = $exception->getMessage();
		}
		try {
			$this->validate_project_settings_public_reference($input["public_project_reference"] ?? null);
		} catch (\InvalidArgumentException $exception) {
			$errors["public_project_reference"] = $exception->getMessage();
		}

		$backgroundMode = $input["background_image_mode"] ?? null;
		if (!$this->is_valid_background_image_mode($backgroundMode)) {
			$errors["background_image_mode"] = "settings_error_background_mode";
		}
		try {
			$this->validate_background_image_rotation($input["background_image_rotation"] ?? null);
		} catch (\InvalidArgumentException $exception) {
			$errors["background_image_rotation"] = $exception->getMessage();
		}

		if ($backgroundMode === self::BACKGROUND_IMAGE_CUSTOM && !$hasPendingCustomImage) {
			$existingImage = $this->custom_background_image_details();
			if ($removeCustomImage || !$existingImage["available"]) {
				$errors["custom_background_image"] = "settings_error_custom_image_required";
			}
		}
		return $errors;
	}

	/**
	 * @param array<string, mixed> $input
	 * @return bool
	 */
	private function remove_custom_background_image_requested($input)
	{
		if (!is_array($input)) {
			return false;
		}
		return in_array($input["remove_custom_background_image"] ?? null, array(true, 1, "1", "true", "on"), true);
	}

	/**
	 * @param array<string, mixed>|null $uploadedFile
	 * @return bool
	 */
	private function has_pending_custom_background_image($uploadedFile)
	{
		if (!is_array($uploadedFile) || !array_key_exists("error", $uploadedFile)) {
			return false;
		}
		if (!is_int($uploadedFile["error"]) && !ctype_digit((string) $uploadedFile["error"])) {
			return true;
		}
		return (int) $uploadedFile["error"] !== UPLOAD_ERR_NO_FILE;
	}

	/**
	 * @param array<string, mixed>|null $uploadedFile
	 * @return string|null Normalized PNG bytes, or null when no file was supplied.
	 */
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
		if (
			!isset($uploadedFile["size"]) || !is_numeric($uploadedFile["size"])
			|| (int) $uploadedFile["size"] < 1
			|| (int) $uploadedFile["size"] > Renderer::MAX_CUSTOM_BACKGROUND_IMAGE_UPLOAD_BYTES
		) {
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

	/**
	 * @param array<string, mixed>|null $uploadedFile
	 * @return string Safe display name for REDCap file storage.
	 */
	private function custom_background_image_upload_name($uploadedFile)
	{
		$fallbackName = "watermarked-signature-background.png";
		if (!is_array($uploadedFile) || !isset($uploadedFile["name"]) || !is_string($uploadedFile["name"])) {
			return $fallbackName;
		}

		$name = basename(str_replace("\\", "/", $uploadedFile["name"]));
		$name = trim((string) preg_replace('/[\x00-\x1F\x7F]/', "", $name));
		return $name === "" ? $fallbackName : $name;
	}

	/**
	 * @param string $contents Normalized PNG bytes.
	 * @param string $fileName
	 * @param int $projectId
	 * @return int New edoc ID.
	 */
	private function store_normalized_custom_background_image($contents, $fileName, $projectId)
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
				"name" => $fileName,
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

	/**
	 * @param int|string|null $projectId
	 * @return bool
	 */
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

	/**
	 * @param int|string $projectId
	 * @return int Authorized project ID.
	 */
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

	/**
	 * @param mixed $mode
	 * @return bool
	 */
	private function is_valid_background_image_mode($mode)
	{
		return is_string($mode) && in_array($mode, array(
			self::BACKGROUND_IMAGE_REDCAP,
			self::BACKGROUND_IMAGE_CUSTOM,
			self::BACKGROUND_IMAGE_NONE
		), true);
	}

	/**
	 * @param mixed $reference
	 * @return bool
	 */
	private function is_valid_public_project_reference($reference)
	{
		return $this->is_valid_reference_component($reference, Renderer::MAX_LEGACY_PROJECT_REFERENCE_LENGTH);
	}

	/**
	 * @param mixed $reference
	 * @return bool
	 */
	private function is_valid_new_public_project_reference($reference)
	{
		return $this->is_valid_reference_component($reference, Renderer::MAX_PROJECT_REFERENCE_LENGTH);
	}

	/**
	 * @param mixed $reference
	 * @return bool
	 */
	private function is_valid_field_reference($reference)
	{
		return $this->is_valid_reference_component($reference, Renderer::MAX_FIELD_REFERENCE_LENGTH);
	}

	/**
	 * @param mixed $reference
	 * @param int $maximumLength
	 * @return bool
	 */
	private function is_valid_reference_component($reference, $maximumLength)
	{
		return $reference === null
			|| (is_string($reference)
				&& strlen($reference) <= $maximumLength
				&& preg_match('/^[A-Za-z0-9][A-Za-z0-9 ._\/-]*$/D', $reference));
	}

	/**
	 * Analyse a quoted action-tag parameter without modifying the value shown
	 * to project designers.  The usable reference is still trimmed, but every
	 * diagnostic position refers to the original quoted parameter.
	 *
	 * @param string $rawReference
	 * @return array{raw_value:string,reference_value:string,reference_length:int,diagnostics:array<int,array{code:string,positions:array<int,int>,maximum_length:?int}>}
	 */
	private function field_reference_value_analysis($rawReference)
	{
		$rawReference = (string) $rawReference;
		$rawCharacters = $this->reference_characters($rawReference);
		$start = 0;
		$end = count($rawCharacters);
		while ($start < $end && $this->is_trimmed_reference_whitespace($rawCharacters[$start])) {
			$start++;
		}
		while ($end > $start && $this->is_trimmed_reference_whitespace($rawCharacters[$end - 1])) {
			$end--;
		}

		$referenceCharacters = array_slice($rawCharacters, $start, $end - $start);
		$reference = implode('', $referenceCharacters);
		$referenceLength = count($referenceCharacters);
		$diagnostics = array();
		if ($referenceLength === 0) {
			$diagnostics[] = $this->field_reference_diagnostic('field_reference_empty');
			return array(
				'raw_value' => $rawReference,
				'reference_value' => $reference,
				'reference_length' => 0,
				'diagnostics' => $diagnostics
			);
		}

		if ($referenceLength > Renderer::MAX_FIELD_REFERENCE_LENGTH) {
			$positions = array();
			for ($index = Renderer::MAX_FIELD_REFERENCE_LENGTH; $index < $referenceLength; $index++) {
				$positions[] = $start + $index + 1;
			}
			$diagnostics[] = $this->field_reference_diagnostic(
				'field_reference_too_long',
				$positions,
				Renderer::MAX_FIELD_REFERENCE_LENGTH
			);
		}

		if (!$this->is_valid_reference_start_character($referenceCharacters[0])) {
			$diagnostics[] = $this->field_reference_diagnostic(
				'field_reference_invalid_start',
				array($start + 1)
			);
		}

		$invalidCharacterPositions = array();
		foreach ($referenceCharacters as $index => $character) {
			if (!$this->is_valid_reference_character($character)) {
				$invalidCharacterPositions[] = $start + $index + 1;
			}
		}
		if (!empty($invalidCharacterPositions)) {
			$diagnostics[] = $this->field_reference_diagnostic(
				'field_reference_invalid_characters',
				$invalidCharacterPositions
			);
		}

		return array(
			'raw_value' => $rawReference,
			'reference_value' => $reference,
			'reference_length' => $referenceLength,
			'diagnostics' => $diagnostics
		);
	}

	/**
	 * @param string $reference
	 * @param int $maximumLength
	 * @return array<int,array{code:string,positions:array<int,int>,maximum_length:?int}>
	 */
	private function reference_length_diagnostics($reference, $maximumLength)
	{
		$positions = array();
		foreach ($this->reference_characters($reference) as $index => $_) {
			if ($index >= $maximumLength) {
				$positions[] = $index + 1;
			}
		}
		return empty($positions)
			? array()
			: array($this->field_reference_diagnostic('field_reference_too_long', $positions, $maximumLength));
	}

	/**
	 * @param string $code
	 * @param array<int,int> $positions
	 * @param int|null $maximumLength
	 * @return array{code:string,positions:array<int,int>,maximum_length:?int}
	 */
	private function field_reference_diagnostic($code, $positions = array(), $maximumLength = null)
	{
		return array(
			'code' => (string) $code,
			'positions' => array_values($positions),
			'maximum_length' => $maximumLength
		);
	}

	/**
	 * @param string $reference
	 * @return array<int,string>
	 */
	private function reference_characters($reference)
	{
		$characters = preg_split('//u', (string) $reference, -1, PREG_SPLIT_NO_EMPTY);
		return is_array($characters) ? $characters : str_split((string) $reference);
	}

	/**
	 * @param string $reference
	 * @return int
	 */
	private function reference_character_length($reference)
	{
		return count($this->reference_characters($reference));
	}

	/**
	 * @param string $character
	 * @return bool
	 */
	private function is_trimmed_reference_whitespace($character)
	{
		return in_array($character, array(" ", "\t", "\n", "\r", "\0", "\x0B"), true);
	}

	/**
	 * @param string $character
	 * @return bool
	 */
	private function is_valid_reference_start_character($character)
	{
		return preg_match('/^[A-Za-z0-9]$/D', $character) === 1;
	}

	/**
	 * @param string $character
	 * @return bool
	 */
	private function is_valid_reference_character($character)
	{
		return preg_match('/^[A-Za-z0-9 ._\/-]$/D', $character) === 1;
	}

	/**
	 * @param mixed $error
	 * @return bool
	 */
	private function is_valid_field_reference_error($error)
	{
		return $error === null || in_array($error, array(
			'invalid_action_tag_parameter',
			'field_reference_parameter_format',
			'field_reference_empty',
			'field_reference_too_long',
			'field_reference_invalid_start',
			'field_reference_invalid_characters',
			'multiple_action_tags',
			'project_reference_too_long'
		), true);
	}

	/**
	 * @param string $error
	 * @return int|null
	 */
	private function field_reference_error_maximum_length($error)
	{
		if ($error === 'field_reference_too_long') {
			return Renderer::MAX_FIELD_REFERENCE_LENGTH;
		}
		if ($error === 'project_reference_too_long') {
			return Renderer::MAX_PROJECT_REFERENCE_LENGTH;
		}
		return null;
	}

	/**
	 * @param mixed $value
	 * @return bool
	 */
	private function is_valid_field_reference_error_value($value)
	{
		// This is the literal quoted action-tag parameter.  It is signed before
		// returning to the browser and escaped again before any HTML output.
		return $value === null || (is_string($value) && strlen($value) <= 65535);
	}

	/**
	 * @param mixed $length
	 * @return bool
	 */
	private function is_valid_field_reference_error_length($length)
	{
		return $length === null || (is_int($length) && $length >= 0 && $length <= 65535);
	}

	/**
	 * @param mixed $diagnostics
	 * @return bool
	 */
	private function is_valid_field_reference_diagnostics($diagnostics)
	{
		if (!is_array($diagnostics) || count($diagnostics) > 3) {
			return false;
		}
		foreach ($diagnostics as $diagnostic) {
			if (!is_array($diagnostic) || !$this->is_valid_field_reference_error($diagnostic['code'] ?? null)) {
				return false;
			}
			if (!isset($diagnostic['positions']) || !is_array($diagnostic['positions']) || count($diagnostic['positions']) > 65535) {
				return false;
			}
			foreach ($diagnostic['positions'] as $position) {
				if (!is_int($position) || $position < 1 || $position > 65535) {
					return false;
				}
			}
			if (
				array_key_exists('maximum_length', $diagnostic)
				&& $diagnostic['maximum_length'] !== null
				&& (!is_int($diagnostic['maximum_length']) || $diagnostic['maximum_length'] < 1 || $diagnostic['maximum_length'] > 65535)
			) {
				return false;
			}
		}
		return true;
	}

	/**
	 * @param int $projectId
	 * @return int
	 */
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
