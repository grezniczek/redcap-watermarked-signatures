<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Verification;

use Throwable;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;

/**
 * Administrator-only adapter for global exact signature verification.
 */
class AdministratorVerificationController
{
	const DETAIL_CAPTURED_ENCRYPTED = 'sigwm_captured_encrypted';
	const DETAIL_NOT_CAPTURED = 'sigwm_not_captured';
	const DETAIL_NOT_AVAILABLE = 'sigwm_not_available';

	/** @var \DE\RUB\WatermarkedSignaturesExternalModule\Storage\LogRepository */
	private $repository;

	/** @var VerificationService */
	private $service;

	/** @var object|null */
	private $econsentIpService;

	/** @var bool */
	private $canRevealEconsentIps;

	/**
	 * @param \DE\RUB\WatermarkedSignaturesExternalModule\Storage\LogRepository $repository
	 * @param VerificationService $service
	 * @return void
	 */
	public function __construct($repository, $service, $econsentIpService = null, $canRevealEconsentIps = false)
	{
		if (!is_object($repository)
			|| !method_exists($repository, 'findDiagnosticEventsByEdocId')
			|| !method_exists($repository, 'findRecordRenameEventsByCurrentRecord')) {
			throw new \InvalidArgumentException('The repository must provide diagnostic and record-rename lookup methods.');
		}
		if (!is_object($service) || !method_exists($service, 'verify')) {
			throw new \InvalidArgumentException('The verification service must provide verify().');
		}
		if ($econsentIpService !== null && (!is_object($econsentIpService) || !method_exists($econsentIpService, 'compare'))) {
			throw new \InvalidArgumentException('The e-Consent IP service must provide compare().');
		}
		$this->repository = $repository;
		$this->service = $service;
		$this->econsentIpService = $econsentIpService;
		// The constructor's boolean is a capability granted by the module
		// factory. Enforce the Database Query Tool's own Control Center
		// conditions here as defense in depth before plaintext can be returned.
		$this->canRevealEconsentIps = $canRevealEconsentIps === true
			&& DatabaseQueryToolAccess::canAccessDatabaseQueryTool();
	}

	/**
	 * @param mixed $captureReference
	 * @return array<string, mixed>
	 */
	public function verify($captureReference)
	{
		$normalizedReference = ReferenceGenerator::normalizeCaptureReference($captureReference);
		if ($normalizedReference === null) {
			return $this->present($this->service->verify($captureReference, null), array(), 'capture_reference', $captureReference);
		}

		try {
			$result = $this->service->verify($normalizedReference, null);
			$upload = isset($result['upload']) && is_array($result['upload']) ? $result['upload'] : array();
			$edocId = isset($upload['edoc_id']) && is_numeric($upload['edoc_id'])
				? (int) $upload['edoc_id']
				: 0;
			$diagnostics = $edocId > 0
				? $this->repository->findDiagnosticEventsByEdocId($edocId)
				: array();
			return $this->present($result, $this->appendRecordRenameDiagnostics($diagnostics, $result), 'capture_reference', $normalizedReference);
		} catch (Throwable $exception) {
			return $this->technicalFailure($normalizedReference, 'capture_reference', $normalizedReference);
		}
	}

	/**
	 * @param mixed $edocId
	 * @return array<string, mixed>
	 */
	public function verifyEdocId($edocId)
	{
		if ((!is_int($edocId) && !(is_string($edocId) && ctype_digit($edocId))) || (int) $edocId < 1) {
			return $this->invalidEdocId($edocId);
		}
		$edocId = (int) $edocId;

		try {
			$diagnostics = $this->repository->findDiagnosticEventsByEdocId($edocId);
			$upload = $this->repository->findUploadByEdocId($edocId);
			if ($upload === null) {
				return $this->unknownEdocId($edocId, $diagnostics);
			}
			$captureReference = ReferenceGenerator::normalizeCaptureReference($upload['capture_ref'] ?? null);
			if ($captureReference === null) {
				return $this->technicalFailure(null, 'edoc_id', $edocId, $diagnostics);
			}
			$result = $this->service->verify($captureReference, null);
			return $this->present($result, $this->appendRecordRenameDiagnostics($diagnostics, $result), 'edoc_id', $edocId);
		} catch (Throwable $exception) {
			return $this->technicalFailure(null, 'edoc_id', $edocId);
		}
	}

	/**
	 * @param array<string, mixed> $result
	 * @param array<int, array<string, mixed>> $diagnostics
	 * @param string $lookupType
	 * @param mixed $lookupValue
	 * @return array<string, mixed>
	 */
	private function present($result, $diagnostics, $lookupType, $lookupValue)
	{
		$result = $this->withEconsentIpDiagnostic($result);
		$upload = isset($result['upload']) && is_array($result['upload']) ? $result['upload'] : array();
		$binding = isset($result['binding']) && is_array($result['binding']) ? $result['binding'] : array();
		$details = array();

		$this->copy($details, $upload, array(
			'capture_ref', 'context_ref', 'anchor', 'capture_origin',
			'capture_username', 'captured_at', 'edoc_id', 'file_sha256',
			'project_reference', 'field_reference', 'background_image_mode',
			'background_image_effective_mode', 'background_image_sha256', 'background_image_rotation',
			'watermark_version'
		));
		$this->copy($details, $binding, array(
			'event_id', 'instrument', 'field', 'repeat_type',
			'repeat_instrument', 'repeat_instance', 'bound_at', 'save_origin',
			'save_username'
		));
		$econsentIpDiagnostic = $result['econsent_ip_diagnostic'] ?? null;
		if ($this->hasTrustedEconsentIpContext($result, $binding)) {
			$details['econsent_ip_system_setting_enabled'] = $binding['econsent_ip_system_setting_enabled'];
			$this->appendEconsentIpDetails($details, $binding, $econsentIpDiagnostic);
		}
		$details['record_id'] = $result['current_record_id'] ?? ($binding['record_id'] ?? null);
		$this->copyMapped($details, $upload, array(
			'pid' => 'upload_project_id',
			'_project_id' => 'upload_log_project_id',
			'_log_id' => 'upload_log_id'
		));
		$this->copyMapped($details, $binding, array(
			'pid' => 'binding_project_id',
			'_project_id' => 'binding_log_project_id',
			'_log_id' => 'binding_log_id'
		));

		return array(
			'status' => $result['status'] ?? 'incomplete',
			'binding_state' => $result['binding_state'] ?? 'unknown',
			'integrity' => $result['integrity'] ?? 'not_checked',
			'current_state' => $result['current_state'] ?? 'unknown',
			'capture_ref' => $result['capture_ref'] ?? null,
			'checks' => isset($result['checks']) && is_array($result['checks']) ? $result['checks'] : array(),
			'issues' => isset($result['issues']) && is_array($result['issues']) ? $result['issues'] : array(),
			'edoc' => isset($result['edoc']) && is_array($result['edoc']) ? $result['edoc'] : null,
			'econsent_ip_diagnostic' => isset($result['econsent_ip_diagnostic']) && is_array($result['econsent_ip_diagnostic'])
				? $result['econsent_ip_diagnostic']
				: null,
			'can_reveal_econsent_ips' => $this->canRevealEconsentIps,
			'details' => $details,
			'field_url' => RedcapFieldLink::create($binding, $result['current_record_id'] ?? null),
			'diagnostics' => $this->presentDiagnostics($diagnostics),
			'lookup_type' => $lookupType,
			'lookup_value' => $lookupValue
		);
	}

	/**
	 * @param array<string, mixed> $result
	 * @return array<string, mixed>
	 */
	private function withEconsentIpDiagnostic($result)
	{
		if ($this->econsentIpService === null || !is_array($result)) {
			return $result;
		}
		$binding = isset($result['binding']) && is_array($result['binding']) ? $result['binding'] : null;
		$checks = isset($result['checks']) && is_array($result['checks']) ? $result['checks'] : array();
		if ($binding === null || ($checks['binding_mac'] ?? null) !== true) {
			return $result;
		}
		if ((int) ($binding['v'] ?? 0) >= 3 && ($checks['binding_econsent_ip_mac'] ?? null) !== true) {
			return $result;
		}
		try {
			$diagnostic = $this->econsentIpService->compare(
				$binding,
				$result['current_record_id'] ?? null,
				$this->canRevealEconsentIps
			);
			if (is_array($diagnostic) && ($diagnostic['status'] ?? null) !== 'not_applicable') {
				if (!$this->canRevealEconsentIps) {
					unset($diagnostic['signature_upload_ip'], $diagnostic['econsent_submission_ip']);
				}
				$result['econsent_ip_diagnostic'] = $diagnostic;
			}
		} catch (Throwable $exception) {
			// The e-Consent comparison is not a signature-integrity check.
		}
		return $result;
	}

	/**
	 * @param array<string, mixed> $result
	 * @param array<string, mixed> $binding
	 * @return bool
	 */
	private function hasTrustedEconsentIpContext($result, $binding)
	{
		$checks = isset($result['checks']) && is_array($result['checks']) ? $result['checks'] : array();
		return (int) ($binding['v'] ?? 0) >= 3
			&& ($checks['binding_econsent_ip_mac'] ?? null) === true
			&& ($binding['econsent_survey_id'] ?? null) !== null
			&& array_key_exists('econsent_ip_system_setting_enabled', $binding);
	}

	/**
	 * The Control Center page is available to a broader administrative group
	 * than the Database Query Tool. Preserve two stable IP rows for applicable
	 * evidence, but use a non-sensitive state label unless the shared DQT gate
	 * authorized plaintext disclosure.
	 *
	 * @param array<string, mixed> $details
	 * @param array<string, mixed> $binding
	 * @param array<string, mixed>|null $diagnostic
	 * @return void
	 */
	private function appendEconsentIpDetails(&$details, $binding, $diagnostic)
	{
		if (($binding['econsent_ip_capture_status'] ?? null) !== 'captured') {
			$details['signature_upload_ip'] = self::DETAIL_NOT_CAPTURED;
			$details['econsent_submission_ip'] = self::DETAIL_NOT_CAPTURED;
			return;
		}

		if (!$this->canRevealEconsentIps || !is_array($diagnostic)) {
			$details['signature_upload_ip'] = self::DETAIL_CAPTURED_ENCRYPTED;
			$details['econsent_submission_ip'] = self::DETAIL_CAPTURED_ENCRYPTED;
			return;
		}

		$details['signature_upload_ip'] = is_string($diagnostic['signature_upload_ip'] ?? null)
			? $diagnostic['signature_upload_ip']
			: self::DETAIL_NOT_AVAILABLE;
		$details['econsent_submission_ip'] = is_string($diagnostic['econsent_submission_ip'] ?? null)
			? $diagnostic['econsent_submission_ip']
			: self::DETAIL_NOT_AVAILABLE;
	}

	/**
	 * @param array<int, array<string, mixed>> $diagnostics
	 * @return array<int, array<string, mixed>>
	 */
	private function presentDiagnostics($diagnostics)
	{
		if (!is_array($diagnostics)) {
			return array();
		}

		// Present a forensic history with the most recent event first. The
		// indexed timestamp uses sortable REDCap SQL datetime formatting; the
		// log ID makes events from the same second deterministic.
		usort($diagnostics, function ($left, $right) {
			$leftTimestamp = is_array($left) ? (string) ($left['timestamp'] ?? '') : '';
			$rightTimestamp = is_array($right) ? (string) ($right['timestamp'] ?? '') : '';
			if ($leftTimestamp !== $rightTimestamp) {
				return strcmp($rightTimestamp, $leftTimestamp);
			}
			$leftLogId = is_array($left) ? (int) ($left['log_id'] ?? 0) : 0;
			$rightLogId = is_array($right) ? (int) ($right['log_id'] ?? 0) : 0;
			return $rightLogId <=> $leftLogId;
		});

		$presented = array();
		foreach ($diagnostics as $diagnostic) {
			if (!is_array($diagnostic)) {
				continue;
			}
			$entry = array();
			$this->copy($entry, $diagnostic, array(
				'log_id', 'timestamp', 'username', 'project_id', 'record',
				'message', 'edoc_id', 'capture_ref', 'context_ref', 'project_reference', 'anchor',
				'event_id', 'instrument', 'field', 'capture_origin',
				'capture_username', 'save_origin', 'save_username', 'bound_at',
				'technical_message', 'original_log_id', 'binding_log_id',
				'previous_record_id', 'rename_origin', 'rename_username', 'renamed_at'
			));
			if (!empty($entry)) {
				$presented[] = $entry;
			}
		}
		return $presented;
	}

	/**
	 * @param array<int, array<string, mixed>> $diagnostics
	 * @param array<string, mixed> $result
	 * @return array<int, array<string, mixed>>
	 */
	private function appendRecordRenameDiagnostics($diagnostics, $result)
	{
		if (!is_array($diagnostics)) {
			$diagnostics = array();
		}
		$binding = isset($result['binding']) && is_array($result['binding']) ? $result['binding'] : array();
		$projectId = $binding['pid'] ?? null;
		$currentRecordId = $result['current_record_id'] ?? null;
		if (!is_numeric($projectId) || (int) $projectId < 1 || !is_scalar($currentRecordId) || (string) $currentRecordId === '') {
			return $diagnostics;
		}

		$renames = $this->repository->findRecordRenameEventsByCurrentRecord((int) $projectId, (string) $currentRecordId);
		if (!is_array($renames) || empty($renames)) {
			return $diagnostics;
		}
		return array_merge($diagnostics, $renames);
	}

	/**
	 * @param array<string, mixed> $target
	 * @param array<string, mixed> $source
	 * @param array<int, string> $fields
	 * @return void
	 */
	private function copy(&$target, $source, $fields)
	{
		foreach ($fields as $field) {
			if (array_key_exists($field, $source)) {
				$target[$field] = $source[$field];
			}
		}
	}

	/**
	 * @param array<string, mixed> $target
	 * @param array<string, mixed> $source
	 * @param array<string, string> $fields Source-to-target field map.
	 * @return void
	 */
	private function copyMapped(&$target, $source, $fields)
	{
		foreach ($fields as $sourceField => $targetField) {
			if (array_key_exists($sourceField, $source)) {
				$target[$targetField] = $source[$sourceField];
			}
		}
	}

	/**
	 * @param mixed $edocId
	 * @return array<string, mixed>
	 */
	private function invalidEdocId($edocId)
	{
		return array(
			'status' => 'invalid_edoc_id',
			'binding_state' => 'unknown',
			'integrity' => 'not_checked',
			'current_state' => 'unknown',
			'capture_ref' => null,
			'checks' => array(),
			'issues' => array('invalid_edoc_id'),
			'edoc' => null,
			'details' => array(),
			'field_url' => null,
			'diagnostics' => array(),
			'lookup_type' => 'edoc_id',
			'lookup_value' => $edocId
		);
	}

	/**
	 * @param int $edocId
	 * @param array<int, array<string, mixed>> $diagnostics
	 * @return array<string, mixed>
	 */
	private function unknownEdocId($edocId, $diagnostics)
	{
		return array(
			'status' => 'unknown',
			'binding_state' => 'unknown',
			'integrity' => 'not_checked',
			'current_state' => 'unknown',
			'capture_ref' => null,
			'checks' => array(),
			'issues' => array(),
			'edoc' => null,
			'details' => array(),
			'field_url' => null,
			'diagnostics' => $this->presentDiagnostics($diagnostics),
			'lookup_type' => 'edoc_id',
			'lookup_value' => $edocId
		);
	}

	/**
	 * @param string|null $captureReference
	 * @param string $lookupType
	 * @param mixed $lookupValue
	 * @param array<int, array<string, mixed>> $diagnostics
	 * @return array<string, mixed>
	 */
	private function technicalFailure($captureReference, $lookupType, $lookupValue, $diagnostics = array())
	{
		return array(
			'status' => 'invalid',
			'binding_state' => 'unknown',
			'integrity' => 'invalid',
			'current_state' => 'unknown',
			'capture_ref' => $captureReference,
			'checks' => array(),
			'issues' => array('log_integrity_error'),
			'edoc' => null,
			'details' => array(),
			'field_url' => null,
			'diagnostics' => $this->presentDiagnostics($diagnostics),
			'lookup_type' => $lookupType,
			'lookup_value' => $lookupValue
		);
	}
}
