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

    public static function isCaptureReference($value)
    {
        return is_string($value)
            && preg_match('/^S:[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]$/D', $value) === 1;
    }

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

    public static function nonce()
    {
        return Base64Url::encode(random_bytes(18));
    }

    private static function generate($prefix, $characters)
    {
        $encoded = substr(Base32::encode(random_bytes(12)), 0, $characters);
        return $prefix . ':' . Base32::group($encoded);
    }
}
