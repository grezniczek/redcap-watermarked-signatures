<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Crypto;

/**
 * Creates and verifies the MAC protecting an authoritative saved binding.
 */
class BindingMac
{
    private $key;

    private static $definingFields = array(
        'v',
        'edoc_id',
        'anchor',
        'capture_ref',
        'context_ref',
        'record_ref',
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

    public function __construct($key)
    {
        if (!is_string($key) || strlen($key) < 32) {
            throw new \InvalidArgumentException('Binding key must contain at least 32 bytes.');
        }
        $this->key = $key;
    }

    public function create($binding)
    {
        $payload = $this->definingPayload($binding);
        return Base64Url::encode(hash_hmac('sha256', CanonicalJson::encode($payload), $this->key, true));
    }

    public function verify($binding)
    {
        if (!isset($binding['binding_mac']) || !is_string($binding['binding_mac'])) {
            return false;
        }
        return hash_equals($this->create($binding), $binding['binding_mac']);
    }

    public function equals($left, $right)
    {
        return hash_equals(
            CanonicalJson::encode($this->definingPayload($left)),
            CanonicalJson::encode($this->definingPayload($right))
        );
    }

    public function definingPayload($binding)
    {
        if (!is_array($binding)) {
            throw new \InvalidArgumentException('Binding must be an array.');
        }

        $payload = array();
        foreach (self::$definingFields as $field) {
            if (!array_key_exists($field, $binding)) {
                throw new \UnexpectedValueException("Binding property '{$field}' is missing.");
            }
            $payload[$field] = $binding[$field];
        }
        return $payload;
    }
}
