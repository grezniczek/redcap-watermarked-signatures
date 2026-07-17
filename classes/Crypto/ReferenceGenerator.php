<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Crypto;

class ReferenceGenerator
{
    public static function contextReference()
    {
        return self::generate('C', 13);
    }

    public static function captureReference()
    {
        return self::generate('S', 13);
    }

    public static function nonce()
    {
        return Base64Url::encode(random_bytes(18));
    }

    private static function generate($prefix, $characters)
    {
        $encoded = substr(Base32::encode(random_bytes(12)), 0, $characters);
        return $prefix . '-' . Base32::group($encoded);
    }
}
