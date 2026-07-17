<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Crypto;

class Anchor
{
    const VISIBLE_CHARACTERS = 16;

    public static function create($scope, $key)
    {
        $digest = hash_hmac('sha256', CanonicalJson::encode($scope), $key, true);
        $visible = substr(Base32::encode($digest), 0, self::VISIBLE_CHARACTERS);
        return Base32::group($visible);
    }
}
