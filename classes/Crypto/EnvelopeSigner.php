<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Crypto;

class EnvelopeSigner
{
    private $key;

    public function __construct($key)
    {
        if (!is_string($key) || strlen($key) < 32) {
            throw new \InvalidArgumentException('Envelope key must contain at least 32 bytes.');
        }
        $this->key = $key;
    }

    public function sign($payload)
    {
        $json = CanonicalJson::encode($payload);
        $encodedPayload = Base64Url::encode($json);
        $mac = hash_hmac('sha256', $encodedPayload, $this->key, true);

        return $encodedPayload . '.' . Base64Url::encode($mac);
    }

    public function verify($envelope)
    {
        if (!is_string($envelope) || substr_count($envelope, '.') !== 1) {
            throw new \InvalidArgumentException('Malformed signature watermark envelope.');
        }

        list($encodedPayload, $encodedMac) = explode('.', $envelope, 2);
        $providedMac = Base64Url::decode($encodedMac);
        $expectedMac = hash_hmac('sha256', $encodedPayload, $this->key, true);

        if (!hash_equals($expectedMac, $providedMac)) {
            throw new \UnexpectedValueException('Invalid signature watermark envelope MAC.');
        }

        $json = Base64Url::decode($encodedPayload);
        $payload = json_decode($json, true);
        if (!is_array($payload) || json_last_error() !== JSON_ERROR_NONE) {
            throw new \UnexpectedValueException('Invalid signature watermark envelope payload.');
        }

        if (!hash_equals($encodedPayload, Base64Url::encode(CanonicalJson::encode($payload)))) {
            throw new \UnexpectedValueException('The signature watermark envelope is not canonical.');
        }

        return $payload;
    }
}
