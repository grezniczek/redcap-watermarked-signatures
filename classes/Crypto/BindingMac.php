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
        'project_reference',
        'capture_origin',
        'capture_username',
        'save_origin',
        'save_username',
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

    // The save actor and channel describe the first binding event, but are not
    // part of edoc identity. A later save of an already-bound field may occur
    // through another channel or authenticated account and remains idempotent.
    private static $identityFields = array(
        'v',
        'edoc_id',
        'anchor',
        'capture_ref',
        'context_ref',
        'record_ref',
        'project_reference',
        'capture_origin',
        'capture_username',
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
            CanonicalJson::encode($this->payloadForFields($left, self::$identityFields)),
            CanonicalJson::encode($this->payloadForFields($right, self::$identityFields))
        );
    }

    public function definingPayload($binding)
    {
        return $this->payloadForFields($binding, self::$definingFields);
    }

    private function payloadForFields($binding, $fields)
    {
        if (!is_array($binding)) {
            throw new \InvalidArgumentException('Binding must be an array.');
        }

        $payload = array();
        foreach ($fields as $field) {
            if (!array_key_exists($field, $binding)) {
                throw new \UnexpectedValueException("Binding property '{$field}' is missing.");
            }
            $payload[$field] = $binding[$field];
        }
        return $payload;
    }
}
