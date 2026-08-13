<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Verification;

use Throwable;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\BindingMac;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
use DE\RUB\WatermarkedSignaturesExternalModule\Storage\LogRepository;

/**
 * Authorization-aware adapter between the project page and verification core.
 */
class ProjectVerificationController
{
	/** @var int */
	private $projectId;

	/** @var LogRepository */
	private $repository;

	/** @var BindingMac */
	private $bindingMac;

	/** @var VerificationService */
	private $service;

	/** @var ProjectAccessPolicy */
	private $accessPolicy;

	/**
	 * @param int $projectId
	 * @param LogRepository $repository
	 * @param BindingMac $bindingMac
	 * @param VerificationService $service
	 * @param ProjectAccessPolicy $accessPolicy
	 * @return void
	 */
	public function __construct($projectId, $repository, $bindingMac, $service, ProjectAccessPolicy $accessPolicy)
	{
		$this->projectId = (int) $projectId;
		$this->repository = $repository;
		$this->bindingMac = $bindingMac;
		$this->service = $service;
		$this->accessPolicy = $accessPolicy;
	}

	/**
	 * @param mixed $captureReference
	 * @return array<string, mixed>
	 */
	public function verify($captureReference)
	{
		$normalizedReference = ReferenceGenerator::normalizeCaptureReference($captureReference);
		if ($normalizedReference === null) {
			return $this->present($this->service->verify($captureReference, $this->projectId));
		}
		$captureReference = $normalizedReference;

		try {
			$upload = $this->repository->findUploadByCaptureReference($captureReference, $this->projectId);
			if ($upload === null) {
				return $this->present($this->service->verify($captureReference, $this->projectId));
			}
			if (!$this->accessPolicy->canViewUpload($upload)) {
				return $this->accessDenied($captureReference);
			}

			$edocId = isset($upload['edoc_id']) && is_numeric($upload['edoc_id'])
				? (int) $upload['edoc_id']
				: 0;
			if ($edocId < 1) {
				return $this->technicalFailure($captureReference);
			}
			$binding = $this->repository->findBindingByEdocId($edocId);
			if ($binding === null) {
				if ($this->accessPolicy->isDagRestricted()) {
					return $this->accessDenied($captureReference);
				}
				return $this->present($this->service->verify($captureReference, $this->projectId));
			}

			try {
				$trustedBinding = $this->bindingMac->verify($binding);
			} catch (Throwable $exception) {
				$trustedBinding = false;
			}
			if (!$trustedBinding) {
				return $this->technicalFailure($captureReference, 'binding_mac_mismatch');
			}
			// The immutable binding payload retains the record ID at bind
			// time. DAG authorization must use REDCap's current indexed log
			// record after any subsequent rename.
			$bindingForAccess = $binding;
			if (isset($binding['_current_record_id']) && $binding['_current_record_id'] !== null && $binding['_current_record_id'] !== '') {
				$bindingForAccess['record_id'] = (string) $binding['_current_record_id'];
			}
			if (!$this->accessPolicy->canViewBinding($bindingForAccess)) {
				return $this->accessDenied($captureReference);
			}

			return $this->present($this->service->verify($captureReference, $this->projectId));
		} catch (Throwable $exception) {
			return $this->technicalFailure($captureReference, 'log_integrity_error');
		}
	}

	/**
	 * @param array<string, mixed> $result
	 * @return array<string, mixed>
	 */
	private function present($result)
	{
		$upload = isset($result['upload']) && is_array($result['upload']) ? $result['upload'] : array();
		$binding = isset($result['binding']) && is_array($result['binding']) ? $result['binding'] : array();
		$details = array();

		$this->copy($details, $upload, array(
			'capture_ref', 'context_ref', 'anchor', 'capture_origin',
			'capture_username', 'captured_at', 'edoc_id', 'file_sha256',
			'project_reference', 'background_image_mode',
			'background_image_effective_mode', 'background_image_sha256',
			'background_image_rotation'
		));
		$this->copy($details, $binding, array(
			'event_id', 'instrument', 'field', 'repeat_type',
			'repeat_instrument', 'repeat_instance', 'bound_at', 'save_origin',
			'save_username', 'watermark_version'
		));
		$details['record_id'] = $result['current_record_id'] ?? ($binding['record_id'] ?? null);

		return array(
			'status' => $result['status'] ?? 'incomplete',
			'binding_state' => $result['binding_state'] ?? 'unknown',
			'integrity' => $result['integrity'] ?? 'not_checked',
			'current_state' => $result['current_state'] ?? 'unknown',
			'capture_ref' => $result['capture_ref'] ?? null,
			'checks' => isset($result['checks']) && is_array($result['checks']) ? $result['checks'] : array(),
			'issues' => isset($result['issues']) && is_array($result['issues']) ? $result['issues'] : array(),
			'edoc' => isset($result['edoc']) && is_array($result['edoc']) ? $result['edoc'] : null,
			'details' => $details,
			'field_url' => RedcapFieldLink::create($binding, $result['current_record_id'] ?? null)
		);
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
	 * @param string|null $captureReference
	 * @return array<string, mixed>
	 */
	private function accessDenied($captureReference)
	{
		return array(
			'status' => 'access_denied',
			'binding_state' => 'unknown',
			'integrity' => 'not_checked',
			'current_state' => 'unknown',
			'capture_ref' => $captureReference,
			'checks' => array(),
			'issues' => array('not_available_in_authorized_scope'),
			'edoc' => null,
			'details' => array(),
			'field_url' => null
		);
	}

	/**
	 * @param string|null $captureReference
	 * @param string $issue
	 * @return array<string, mixed>
	 */
	private function technicalFailure($captureReference, $issue = 'invalid_upload_provenance')
	{
		return array(
			'status' => 'invalid',
			'binding_state' => 'unknown',
			'integrity' => 'invalid',
			'current_state' => 'unknown',
			'capture_ref' => $captureReference,
			'checks' => array(),
			'issues' => array($issue),
			'edoc' => null,
			'details' => array(),
			'field_url' => null
		);
	}
}
