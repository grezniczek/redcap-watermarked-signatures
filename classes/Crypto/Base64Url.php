<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Crypto;

class Base64Url
{
    public static function encode($bytes)
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function decode($value)
    {
        if (!is_string($value) || !preg_match('/^[A-Za-z0-9_-]*$/', $value)) {
            throw new \InvalidArgumentException('Invalid base64url value.');
        }

        $padding = strlen($value) % 4;
        if ($padding !== 0) {
            $value .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        if ($decoded === false) {
            throw new \InvalidArgumentException('Invalid base64url value.');
        }

        return $decoded;
    }
}
