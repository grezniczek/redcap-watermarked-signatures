<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Crypto;

class ReferenceGenerator
{
	/**
	 * @return string Visible C:-prefixed context reference.
	 */
	public static function contextReference()
	{
		return self::generate('C', 13);
	}

	/**
	 * @return string Visible S:-prefixed capture reference.
	 */
	public static function captureReference()
	{
		return self::generate('S', 13);
	}

	/**
	 * @param mixed $value
	 * @return bool Whether the value is a canonical printed capture reference.
	 */
	public static function isCaptureReference($value)
	{
		return is_string($value)
			&& preg_match('/^S:[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]$/D', $value) === 1;
	}

	/**
	 * @param mixed $value S:-prefixed or printed capture reference.
	 * @return string|null Canonical S:-prefixed reference, or null if invalid.
	 */
	public static function normalizeCaptureReference($value)
	{
		if (!is_string($value)) {
			return null;
		}
		$value = strtoupper(trim($value));
		if (self::isCaptureReference($value)) {
			return $value;
		}
		if (preg_match('/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]$/D', $value)) {
			return 'S:' . $value;
		}
		return null;
	}

	/**
	 * @return string Base64url nonce for a capture envelope.
	 */
	public static function nonce()
	{
		return Base64Url::encode(random_bytes(18));
	}

	/**
	 * @param string $prefix Visible reference prefix without its colon.
	 * @param int $characters Number of ungrouped Base32 characters.
	 * @return string Prefixed and grouped visible reference.
	 */
	private static function generate($prefix, $characters)
	{
		$encoded = substr(Base32::encode(random_bytes(12)), 0, $characters);
		return $prefix . ':' . Base32::group($encoded);
	}
}
