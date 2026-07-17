<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Crypto;

/**
 * Deterministic JSON for all values covered by a MAC.
 */
class CanonicalJson
{
    public static function encode($value)
    {
        $normalized = self::normalize($value);
        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

        if (defined('JSON_THROW_ON_ERROR')) {
            return json_encode($normalized, $flags | JSON_THROW_ON_ERROR);
        }

        $json = json_encode($normalized, $flags);
        if ($json === false) {
            throw new \RuntimeException('Could not encode canonical JSON: ' . json_last_error_msg());
        }

        return $json;
    }

    private static function normalize($value)
    {
        if (!is_array($value)) {
            return $value;
        }

        if (self::isList($value)) {
            return array_map(array(__CLASS__, 'normalize'), $value);
        }

        ksort($value, SORT_STRING);
        foreach ($value as $key => $item) {
            $value[$key] = self::normalize($item);
        }

        return $value;
    }

    private static function isList($value)
    {
        $expected = 0;
        foreach ($value as $key => $_) {
            if ($key !== $expected) {
                return false;
            }
            $expected++;
        }
        return true;
    }
}
