<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Crypto;

/**
 * Crockford-style Base32 encoding without padding.
 *
 * The alphabet omits I, L, O, and U to keep visible identifiers readable.
 */
class Base32
{
	const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

	/**
	 * @param string $bytes Binary input.
	 * @return string Unpadded Crockford-style Base32 text.
	 */
	public static function encode($bytes)
	{
		if (!is_string($bytes)) {
			throw new \InvalidArgumentException('Base32 input must be a string.');
		}

		$output = '';
		$buffer = 0;
		$bitsInBuffer = 0;
		$length = strlen($bytes);

		for ($i = 0; $i < $length; $i++) {
			$buffer = ($buffer << 8) | ord($bytes[$i]);
			$bitsInBuffer += 8;

			while ($bitsInBuffer >= 5) {
				$bitsInBuffer -= 5;
				$output .= self::ALPHABET[($buffer >> $bitsInBuffer) & 31];
			}

			if ($bitsInBuffer > 0) {
				$buffer &= (1 << $bitsInBuffer) - 1;
			} else {
				$buffer = 0;
			}
		}

		if ($bitsInBuffer > 0) {
			$output .= self::ALPHABET[($buffer << (5 - $bitsInBuffer)) & 31];
		}

		return $output;
	}

	/**
	 * @param string $value
	 * @param int $groupSize
	 * @return string Hyphen-separated groups.
	 */
	public static function group($value, $groupSize = 4)
	{
		return implode('-', str_split($value, $groupSize));
	}
}
