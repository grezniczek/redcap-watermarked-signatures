<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Crypto;

class Anchor
{
	const VISIBLE_CHARACTERS = 16;
	const PREFIX = 'A:';

	/**
	 * @param mixed $scope Canonically encoded values that identify the form location.
	 * @param string $key Binary HMAC key.
	 * @return string Visible A:-prefixed anchor.
	 */
	public static function create($scope, $key)
	{
		$digest = hash_hmac('sha256', CanonicalJson::encode($scope), $key, true);
		$visible = substr(Base32::encode($digest), 0, self::VISIBLE_CHARACTERS);
		return self::PREFIX . Base32::group($visible);
	}
}
