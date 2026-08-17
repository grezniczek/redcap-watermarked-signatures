<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Crypto;

class KeyDerivation
{
	const ENVELOPE_INFO = 'sigwm/envelope/v1';
	const ANCHOR_INFO = 'sigwm/anchor/v1';
	const BINDING_INFO = 'sigwm/binding/v1';
	const BINDING_EXTENSION_INFO = 'sigwm/binding-extension/v1';
	const ECONSENT_IP_ENCRYPTION_INFO = 'sigwm/econsent-ip-encryption/v1';
	const ECONSENT_IP_BINDING_INFO = 'sigwm/econsent-ip-binding/v1';
	const REFERENCES_INFO = 'sigwm/references/v1';

	/**
	 * @return string Binary installation-specific secret.
	 */
	public static function instanceSecret()
	{
		$salt = isset($GLOBALS['salt']) ? (string) $GLOBALS['salt'] : '';
		$salt2 = isset($GLOBALS['salt2']) ? (string) $GLOBALS['salt2'] : '';

		if ($salt === '' && $salt2 === '') {
			throw new \RuntimeException('The REDCap installation secret is not available.');
		}

		return hash('sha256', "sigwm/instance/v1\0" . $salt2 . "\0" . $salt, true);
	}

	/**
	 * @param string $purpose Domain-separation context.
	 * @param int $length Requested derived-key length in bytes.
	 * @return string Binary derived key.
	 */
	public static function derive($purpose, $length = 32)
	{
		$secret = self::instanceSecret();

		if (function_exists('hash_hkdf')) {
			return hash_hkdf('sha256', $secret, $length, $purpose, 'sigwm/hkdf/v1');
		}

		// RFC 5869 extract-and-expand fallback for older supported PHP builds.
		$prk = hash_hmac('sha256', $secret, 'sigwm/hkdf/v1', true);
		$output = '';
		$previous = '';
		$counter = 1;

		while (strlen($output) < $length) {
			$previous = hash_hmac('sha256', $previous . $purpose . chr($counter), $prk, true);
			$output .= $previous;
			$counter++;
		}

		return substr($output, 0, $length);
	}
}
