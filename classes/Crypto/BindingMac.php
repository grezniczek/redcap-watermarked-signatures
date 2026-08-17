<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Crypto;

/**
 * Creates and verifies the MAC protecting an authoritative saved binding.
 */
class BindingMac
{
	/** @var string Binary HMAC key. */
	private $key;

	/** @var string|null Binary HMAC key for format-v2 binding extensions. */
	private $extensionKey;

	/** @var string|null Binary HMAC key for format-v3 encrypted IP-capture provenance. */
	private $econsentIpExtensionKey;

	/** @var array<int, string> */
	private static $definingFields = array(
		'v',
		'edoc_id',
		'anchor',
		'capture_ref',
		'context_ref',
		'record_ref',
		'project_reference',
		'capture_origin',
		'capture_username',
		'save_origin',
		'save_username',
		'record_id',
		'pid',
		'event_id',
		'instrument',
		'field',
		'repeat_type',
		'repeat_instrument',
		'repeat_instance',
		'file_sha256',
		'watermark_version'
	);

	/** @var array<int, string> */
	private static $identityFields = array(
		'v',
		'edoc_id',
		'anchor',
		'capture_ref',
		'context_ref',
		'record_ref',
		'project_reference',
		'capture_origin',
		'capture_username',
		'record_id',
		'pid',
		'event_id',
		'instrument',
		'field',
		'repeat_type',
		'repeat_instrument',
		'repeat_instance',
		'file_sha256',
		'watermark_version'
	);

	/** @var array<int, string> Fields in the pre-release v1.0.3 MAC extension. */
	private static $legacyExtensionFields = array(
		'field_reference'
	);

	/** @var array<int, string> Fields protected by the format-v2 extension MAC. */
	private static $extensionFields = array(
		'v',
		'binding_mac',
		'field_reference'
	);

	/** @var array<int, string> Fields protected by the format-v3 IP-capture MAC. */
	private static $econsentIpExtensionFields = array(
		'v',
		'binding_mac',
		'econsent_survey_id',
		'econsent_ip_system_setting_enabled',
		'econsent_ip_capture_status',
		'econsent_signature_ip_ciphertext',
		'data_entry_signature_ip_capture_status',
		'data_entry_signature_ip_ciphertext'
	);

	/** @var array<int, string> Values that must agree for an idempotent v3 IP-capture binding. */
	private static $econsentIpValueFields = array(
		'econsent_survey_id',
		'econsent_ip_system_setting_enabled',
		'econsent_ip_capture_status',
		'econsent_signature_ip_ciphertext',
		'data_entry_signature_ip_capture_status',
		'data_entry_signature_ip_ciphertext'
	);

	/**
	 * @param string $key Binary HMAC key of at least 32 bytes.
	 * @param string|null $extensionKey Independently derived extension-MAC key.
	 * @param string|null $econsentIpExtensionKey Independently derived format-v3 IP-capture MAC key.
	 * @return void
	 */
	public function __construct($key, $extensionKey = null, $econsentIpExtensionKey = null)
	{
		if (!is_string($key) || strlen($key) < 32) {
			throw new \InvalidArgumentException('Binding key must contain at least 32 bytes.');
		}
		if ($extensionKey !== null && (!is_string($extensionKey) || strlen($extensionKey) < 32)) {
			throw new \InvalidArgumentException('Binding extension key must contain at least 32 bytes.');
		}
		if ($econsentIpExtensionKey !== null && (!is_string($econsentIpExtensionKey) || strlen($econsentIpExtensionKey) < 32)) {
			throw new \InvalidArgumentException('IP-capture binding key must contain at least 32 bytes.');
		}
		$this->key = $key;
		$this->extensionKey = $extensionKey;
		$this->econsentIpExtensionKey = $econsentIpExtensionKey;
	}

	/**
	 * @param array<string, mixed> $binding Complete authoritative binding.
	 * @return string Base64url-encoded binding MAC.
	 */
	public function create($binding)
	{
		$payload = $this->definingPayload($binding);
		return Base64Url::encode(hash_hmac('sha256', CanonicalJson::encode($payload), $this->key, true));
	}

	/**
	 * @param array<string, mixed> $binding Complete authoritative binding with its binding_mac value.
	 * @return bool Whether the supplied MAC authenticates the binding.
	 */
	public function verify($binding)
	{
		if (!isset($binding['binding_mac']) || !is_string($binding['binding_mac'])) {
			return false;
		}
		if (hash_equals($this->create($binding), $binding['binding_mac'])) {
			return true;
		}
		return $this->isLegacyFieldReferenceBinding($binding)
			&& hash_equals($this->createLegacyFieldReferenceMac($binding), $binding['binding_mac']);
	}

	/**
	 * Create the independently keyed MAC for a format-v2 binding extension.
	 * Its base MAC binds this small payload to all v1 binding-defining values.
	 *
	 * @param array<string, mixed> $binding Complete authoritative binding with its base binding_mac value.
	 * @return string Base64url-encoded extension MAC.
	 */
	public function createExtension($binding)
	{
		if ($this->extensionKey === null) {
			throw new \LogicException('A binding extension key is required.');
		}
		$payload = $this->payloadForFields($binding, self::$extensionFields);
		return Base64Url::encode(hash_hmac('sha256', CanonicalJson::encode($payload), $this->extensionKey, true));
	}

	/**
	 * @param array<string, mixed> $binding Complete format-v2 binding with its extension MAC value.
	 * @return bool Whether the supplied extension MAC authenticates the binding extension.
	 */
	public function verifyExtension($binding)
	{
		if ($this->extensionKey === null || !isset($binding['binding_extension_mac']) || !is_string($binding['binding_extension_mac'])) {
			return false;
		}
		try {
			return hash_equals($this->createExtension($binding), $binding['binding_extension_mac']);
		} catch (\Throwable $exception) {
			return false;
		}
	}

	/**
	 * Create the independently keyed MAC for the format-v3 encrypted
	 * IP-capture context. The ciphertext remains confidential, while this MAC
	 * makes e-Consent applicability and data-entry capture status immutable.
	 *
	 * @param array<string, mixed> $binding Complete binding with its base MAC value.
	 * @return string Base64url-encoded extension MAC.
	 */
	public function createEconsentIpExtension($binding)
	{
		if ($this->econsentIpExtensionKey === null) {
			throw new \LogicException('An IP-capture binding key is required.');
		}
		$payload = $this->payloadForFields($binding, self::$econsentIpExtensionFields);
		return Base64Url::encode(hash_hmac('sha256', CanonicalJson::encode($payload), $this->econsentIpExtensionKey, true));
	}

	/**
	 * @param array<string, mixed> $binding Complete format-v3 binding with its IP-capture MAC.
	 * @return bool Whether the supplied IP-capture MAC authenticates this extension.
	 */
	public function verifyEconsentIpExtension($binding)
	{
		if ($this->econsentIpExtensionKey === null
			|| !isset($binding['binding_econsent_ip_mac'])
			|| !is_string($binding['binding_econsent_ip_mac'])) {
			return false;
		}
		try {
			return hash_equals($this->createEconsentIpExtension($binding), $binding['binding_econsent_ip_mac']);
		} catch (\Throwable $exception) {
			return false;
		}
	}

	/**
	 * @param array<string, mixed> $left
	 * @param array<string, mixed> $right
	 * @return bool Whether both bindings have the same edoc identity.
	 */
	public function equals($left, $right)
	{
		return hash_equals(
			CanonicalJson::encode($this->payloadForFields($left, self::$identityFields)),
			CanonicalJson::encode($this->payloadForFields($right, self::$identityFields))
		);
	}

	/**
	 * @param array<string, mixed> $left
	 * @param array<string, mixed> $right
	 * @return bool Whether both bindings carry the same optional field-reference value.
	 */
	public function extensionValuesEqual($left, $right)
	{
		$leftHasFieldReference = array_key_exists('field_reference', $left);
		$rightHasFieldReference = array_key_exists('field_reference', $right);
		return $leftHasFieldReference === $rightHasFieldReference
			&& (!$leftHasFieldReference || $left['field_reference'] === $right['field_reference']);
	}

	/**
	 * @param array<string, mixed> $left
	 * @param array<string, mixed> $right
	 * @return bool Whether both bindings have the same v3 IP-capture context.
	 */
	public function econsentIpValuesEqual($left, $right)
	{
		$leftRequires = $this->requiresEconsentIpExtension($left);
		$rightRequires = $this->requiresEconsentIpExtension($right);
		if ($leftRequires !== $rightRequires) {
			return false;
		}
		if (!$leftRequires) {
			return true;
		}
		try {
			return hash_equals(
				CanonicalJson::encode($this->payloadForFields($left, self::$econsentIpValueFields)),
				CanonicalJson::encode($this->payloadForFields($right, self::$econsentIpValueFields))
			);
		} catch (\Throwable $exception) {
			return false;
		}
	}

	/**
	 * @param array<string, mixed> $binding
	 * @return bool Whether this binding format requires the IP-capture MAC.
	 */
	public function requiresEconsentIpExtension($binding)
	{
		return is_array($binding) && (int) ($binding['v'] ?? 0) >= 3;
	}

	/**
	 * @param array<string, mixed> $binding Complete authoritative binding.
	 * @return array<string, mixed> Fields included in the binding MAC.
	 */
	public function definingPayload($binding)
	{
		return $this->payloadForFields($binding, self::$definingFields);
	}

	/**
	 * @param array<string, mixed> $binding
	 * @param array<int, string> $fields
	 * @return array<string, mixed>
	 */
	private function payloadForFields($binding, $fields)
	{
		if (!is_array($binding)) {
			throw new \InvalidArgumentException('Binding must be an array.');
		}

		$payload = array();
		foreach ($fields as $field) {
			if (!array_key_exists($field, $binding)) {
				throw new \UnexpectedValueException("Binding property '{$field}' is missing.");
			}
			$payload[$field] = $binding[$field];
		}
		return $payload;
	}

	/**
	 * Accept the short-lived pre-release format that added field_reference to
	 * the base MAC. Released v1 bindings never contained that extension.
	 *
	 * @param array<string, mixed> $binding
	 * @return bool
	 */
	private function isLegacyFieldReferenceBinding($binding)
	{
		return is_array($binding)
			&& (int) ($binding['v'] ?? 0) === 1
			&& array_key_exists('field_reference', $binding);
	}

	/**
	 * @param array<string, mixed> $binding
	 * @return string Base64url-encoded pre-release extension of the v1 base MAC.
	 */
	private function createLegacyFieldReferenceMac($binding)
	{
		$payload = $this->payloadForFields($binding, self::$definingFields);
		foreach (self::$legacyExtensionFields as $field) {
			if (!array_key_exists($field, $binding)) {
				throw new \UnexpectedValueException("Binding property '{$field}' is missing.");
			}
			$payload[$field] = $binding[$field];
		}
		return Base64Url::encode(hash_hmac('sha256', CanonicalJson::encode($payload), $this->key, true));
	}
}
