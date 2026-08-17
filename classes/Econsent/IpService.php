<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Econsent;

use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\CanonicalJson;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\IpCipher;

/**
 * Captures upload IP evidence and compares the e-Consent subset with the
 * participant-facing e-Consent submission recorded by REDCap.
 *
 * Plaintext addresses never enter an External Module log parameter. They are
 * retained only as authenticated ciphertext in the upload and binding payloads.
 */
class IpService
{
	const STATUS_NOT_APPLICABLE = 'not_applicable';
	const STATUS_CAPTURED = 'captured';
	const STATUS_SYSTEM_DISABLED = 'not_captured_system_disabled';
	const STATUS_CLIENT_IP_UNAVAILABLE = 'not_captured_client_ip_unavailable';

	/** @var IpCipher */
	private $cipher;

	/**
	 * @param IpCipher $cipher
	 * @return void
	 */
	public function __construct(IpCipher $cipher)
	{
		$this->cipher = $cipher;
	}

	/**
	 * Capture the IP-related provenance fields for one signature upload.
	 *
	 * Data-entry captures are always retained as encrypted provenance. The
	 * e-Consent setting and archive comparison remain specific to
	 * participant-facing e-Consent surveys.
	 *
	 * @param \Project $project
	 * @param int|string $projectId
	 * @param int|string $eventId
	 * @param string $instrument
	 * @param string $field
	 * @param string $captureOrigin
	 * @param string $captureReference
	 * @return array<string, mixed>
	 */
	public function capture($project, $projectId, $eventId, $instrument, $field, $captureOrigin, $captureReference)
	{
		$context = $this->emptyContext();
		if ($captureOrigin === 'data_entry') {
			$ip = $this->clientIpAddress();
			if ($ip === null) {
				$context['data_entry_signature_ip_capture_status'] = self::STATUS_CLIENT_IP_UNAVAILABLE;
				return $context;
			}
			try {
				$context['data_entry_signature_ip_ciphertext'] = $this->cipher->encrypt(
					$ip,
					self::associatedData($projectId, $eventId, $instrument, $field, $captureReference)
				);
				$context['data_entry_signature_ip_capture_status'] = self::STATUS_CAPTURED;
			} catch (\Throwable $exception) {
				// This optional forensic evidence must never block the signature.
				$context['data_entry_signature_ip_capture_status'] = self::STATUS_CLIENT_IP_UNAVAILABLE;
			}
			return $context;
		}

		if ($captureOrigin !== 'survey' || !is_object($project)) {
			return $context;
		}

		$surveyId = $project->forms[$instrument]['survey_id'] ?? null;
		if (!is_numeric($surveyId) || (int) $surveyId < 1 || !$this->isEconsentSurvey((int) $surveyId)) {
			return $context;
		}

		$context['econsent_survey_id'] = (int) $surveyId;
		$context['econsent_ip_system_setting_enabled'] = $this->systemIpCaptureEnabled();
		if (!$context['econsent_ip_system_setting_enabled']) {
			$context['econsent_ip_capture_status'] = self::STATUS_SYSTEM_DISABLED;
			return $context;
		}

		$ip = $this->clientIpAddress();
		if ($ip === null) {
			$context['econsent_ip_capture_status'] = self::STATUS_CLIENT_IP_UNAVAILABLE;
			return $context;
		}

		try {
			$context['econsent_signature_ip_ciphertext'] = $this->cipher->encrypt(
				$ip,
				self::associatedData($projectId, $eventId, $instrument, $field, $captureReference)
			);
			$context['econsent_ip_capture_status'] = self::STATUS_CAPTURED;
		} catch (\Throwable $exception) {
			// Preserve the lack of a comparable value as binding provenance. The
			// signature upload must not fail solely because optional audit data
			// could not be encrypted.
			$context['econsent_ip_capture_status'] = self::STATUS_CLIENT_IP_UNAVAILABLE;
		}

		return $context;
	}

	/**
	 * Compare a trusted binding's encrypted upload IP with REDCap's e-Consent
	 * PDF-archive IP. Plaintext values are returned only when $revealIps is true.
	 *
	 * @param array<string, mixed> $binding
	 * @param string|null $currentRecordId
	 * @param bool $revealIps
	 * @return array<string, mixed>|null
	 */
	public function compare($binding, $currentRecordId, $revealIps)
	{
		if (!is_array($binding) || !array_key_exists('econsent_ip_capture_status', $binding)) {
			return null; // Historical binding format: the capture was not designed to retain this evidence.
		}

		$status = $binding['econsent_ip_capture_status'];
		if ($status === self::STATUS_NOT_APPLICABLE) {
			return array('status' => self::STATUS_NOT_APPLICABLE, 'warning' => false);
		}
		if ($status === self::STATUS_SYSTEM_DISABLED) {
			return array('status' => 'not_tested_system_disabled', 'warning' => false);
		}
		if ($status !== self::STATUS_CAPTURED) {
			return array('status' => 'not_tested_signature_ip_unavailable', 'warning' => false);
		}

		$recordId = is_scalar($currentRecordId) && (string) $currentRecordId !== ''
			? (string) $currentRecordId
			: (is_scalar($binding['record_id'] ?? null) ? (string) $binding['record_id'] : '');
		$surveyId = $binding['econsent_survey_id'] ?? null;
		if ($recordId === '' || !is_numeric($surveyId) || (int) $surveyId < 1) {
			return array('status' => 'not_tested_econsent_context_unavailable', 'warning' => false);
		}

		try {
			$signatureIp = $this->cipher->decrypt(
				$binding['econsent_signature_ip_ciphertext'] ?? '',
				self::associatedData(
					$binding['pid'] ?? null,
					$binding['event_id'] ?? null,
					$binding['instrument'] ?? null,
					$binding['field'] ?? null,
					$binding['capture_ref'] ?? null
				)
			);
		} catch (\Throwable $exception) {
			return array('status' => 'not_tested_signature_ip_unreadable', 'warning' => false);
		}

		$archive = $this->storedConsentArchive(
			$recordId,
			$binding['event_id'] ?? null,
			(int) $surveyId,
			$binding['repeat_instance'] ?? 1
		);
		if ($archive === null) {
			return $this->withIps(array('status' => 'not_tested_econsent_submission_missing', 'warning' => false), $signatureIp, null, $revealIps);
		}
		$storedIp = $archive['ip'] ?? null;
		if (!is_string($storedIp) || filter_var($storedIp, FILTER_VALIDATE_IP) === false) {
			return $this->withIps(array('status' => 'not_tested_econsent_ip_unavailable', 'warning' => false), $signatureIp, null, $revealIps);
		}

		$matches = $this->ipAddressesMatch($signatureIp, $storedIp);
		return $this->withIps(array(
			'status' => $matches ? 'match' : 'mismatch',
			'warning' => !$matches
		), $signatureIp, $storedIp, $revealIps);
	}

	/**
	 * Restore a trusted data-entry upload IP only when the caller has already
	 * authorized plaintext disclosure. Unlike e-Consent evidence, this has no
	 * corresponding survey archive value to compare.
	 *
	 * @param array<string, mixed> $binding
	 * @param bool $revealIps
	 * @return array<string, mixed>|null
	 */
	public function dataEntrySignatureIp($binding, $revealIps)
	{
		if (!is_array($binding) || !array_key_exists('data_entry_signature_ip_capture_status', $binding)) {
			return null;
		}

		$status = $binding['data_entry_signature_ip_capture_status'];
		if ($status === self::STATUS_NOT_APPLICABLE) {
			return array('status' => self::STATUS_NOT_APPLICABLE);
		}
		if ($status !== self::STATUS_CAPTURED) {
			return array('status' => 'not_captured');
		}
		if (!$revealIps) {
			return array('status' => self::STATUS_CAPTURED);
		}

		try {
			$ip = $this->cipher->decrypt(
				$binding['data_entry_signature_ip_ciphertext'] ?? '',
				self::associatedData(
					$binding['pid'] ?? null,
					$binding['event_id'] ?? null,
					$binding['instrument'] ?? null,
					$binding['field'] ?? null,
					$binding['capture_ref'] ?? null
				)
			);
			return array('status' => self::STATUS_CAPTURED, 'signature_upload_ip' => $ip);
		} catch (\Throwable $exception) {
			return array('status' => 'not_available');
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private function emptyContext()
	{
		return array(
			'econsent_survey_id' => null,
			'econsent_ip_system_setting_enabled' => null,
			'econsent_ip_capture_status' => self::STATUS_NOT_APPLICABLE,
			'econsent_signature_ip_ciphertext' => null,
			'data_entry_signature_ip_capture_status' => self::STATUS_NOT_APPLICABLE,
			'data_entry_signature_ip_ciphertext' => null
		);
	}

	/**
	 * @param int $surveyId
	 * @return bool
	 */
	private function isEconsentSurvey($surveyId)
	{
		if (!class_exists('\\Econsent') || !method_exists('\\Econsent', 'econsentEnabledForSurvey')) {
			return false;
		}
		try {
			return \Econsent::econsentEnabledForSurvey($surveyId) === true;
		} catch (\Throwable $exception) {
			return false;
		}
	}

	/** @return bool */
	private function systemIpCaptureEnabled()
	{
		return (string) ($GLOBALS['pdf_econsent_system_ip'] ?? '') === '1';
	}

	/** @return string|null */
	private function clientIpAddress()
	{
		if (!class_exists('\\System') || !method_exists('\\System', 'clientIpAddress')) {
			return null;
		}
		try {
			$ip = \System::clientIpAddress();
			return is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : null;
		} catch (\Throwable $exception) {
			return null;
		}
	}

	/**
	 * @param string $recordId
	 * @param mixed $eventId
	 * @param int $surveyId
	 * @param mixed $instance
	 * @return array<string, mixed>|null
	 */
	private function storedConsentArchive($recordId, $eventId, $surveyId, $instance)
	{
		if (!class_exists('\\Econsent') || !method_exists('\\Econsent', 'getAttributesOfStoredConsentForm') || !is_numeric($eventId)) {
			return null;
		}
		$instance = is_numeric($instance) && (int) $instance > 0 ? (int) $instance : 1;
		try {
			$archive = \Econsent::getAttributesOfStoredConsentForm($recordId, (int) $eventId, $surveyId, $instance);
			return is_array($archive) ? $archive : null;
		} catch (\Throwable $exception) {
			return null;
		}
	}

	/**
	 * @param array<string, mixed> $result
	 * @param string $signatureIp
	 * @param string|null $storedIp
	 * @param bool $revealIps
	 * @return array<string, mixed>
	 */
	private function withIps($result, $signatureIp, $storedIp, $revealIps)
	{
		if ($revealIps) {
			$result['signature_upload_ip'] = $signatureIp;
			$result['econsent_submission_ip'] = $storedIp;
		}
		return $result;
	}

	/**
	 * Compare address bytes rather than their presentation so equivalent IPv6
	 * representations do not produce a misleading diagnostic warning.
	 *
	 * @param string $left
	 * @param string $right
	 * @return bool
	 */
	private function ipAddressesMatch($left, $right)
	{
		$leftBytes = function_exists('inet_pton') ? inet_pton($left) : false;
		$rightBytes = function_exists('inet_pton') ? inet_pton($right) : false;
		if (is_string($leftBytes) && is_string($rightBytes)) {
			return hash_equals($leftBytes, $rightBytes);
		}
		return hash_equals($left, $right);
	}

	/**
	 * @param mixed $projectId
	 * @param mixed $eventId
	 * @param mixed $instrument
	 * @param mixed $field
	 * @param mixed $captureReference
	 * @return string
	 */
	public static function associatedData($projectId, $eventId, $instrument, $field, $captureReference)
	{
		return CanonicalJson::encode(array(
			'v' => 1,
			'pid' => is_numeric($projectId) ? (int) $projectId : null,
			'event_id' => is_numeric($eventId) ? (int) $eventId : null,
			'instrument' => is_string($instrument) ? $instrument : null,
			'field' => is_string($field) ? $field : null,
			'capture_ref' => is_string($captureReference) ? $captureReference : null
		));
	}

	/**
	 * @param array<string, mixed> $context
	 * @return bool
	 */
	public static function isValidCaptureContext($context)
	{
		if (!is_array($context)) {
			return false;
		}
		$required = array(
			'econsent_survey_id',
			'econsent_ip_system_setting_enabled',
			'econsent_ip_capture_status',
			'econsent_signature_ip_ciphertext'
		);
		foreach ($required as $field) {
			if (!array_key_exists($field, $context)) {
				return false;
			}
		}
		$status = $context['econsent_ip_capture_status'];
		$surveyId = $context['econsent_survey_id'];
		$enabled = $context['econsent_ip_system_setting_enabled'];
		$ciphertext = $context['econsent_signature_ip_ciphertext'];
		if ($status === self::STATUS_NOT_APPLICABLE) {
			return $surveyId === null && $enabled === null && $ciphertext === null;
		}
		if (!is_numeric($surveyId) || (int) $surveyId < 1 || !is_bool($enabled)) {
			return false;
		}
		if ($status === self::STATUS_SYSTEM_DISABLED) {
			return $enabled === false && $ciphertext === null;
		}
		if ($status === self::STATUS_CLIENT_IP_UNAVAILABLE) {
			return $enabled === true && $ciphertext === null;
		}
		return $status === self::STATUS_CAPTURED
			&& $enabled === true
			&& self::isCiphertext($ciphertext);
	}

	/**
	 * @param array<string, mixed> $context
	 * @param string $captureOrigin
	 * @return bool
	 */
	public static function isValidDataEntryCaptureContext($context, $captureOrigin)
	{
		if (!is_array($context)
			|| !array_key_exists('data_entry_signature_ip_capture_status', $context)
			|| !array_key_exists('data_entry_signature_ip_ciphertext', $context)) {
			return false;
		}

		$status = $context['data_entry_signature_ip_capture_status'];
		$ciphertext = $context['data_entry_signature_ip_ciphertext'];
		if ($captureOrigin !== 'data_entry') {
			return $status === self::STATUS_NOT_APPLICABLE && $ciphertext === null;
		}
		if ($status === self::STATUS_CLIENT_IP_UNAVAILABLE) {
			return $ciphertext === null;
		}
		return $status === self::STATUS_CAPTURED && self::isCiphertext($ciphertext);
	}

	/** @return bool */
	private static function isCiphertext($ciphertext)
	{
		return is_string($ciphertext)
			&& preg_match('/^' . IpCipher::FORMAT . '\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$/', $ciphertext) === 1;
	}
}
