<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Crypto;

/**
 * Encrypts respondent IP addresses before they enter the External Module log.
 *
 * The log can be viewed by people who do not have a need to know an IP
 * address, so the ciphertext is authenticated encryption rather than a hash.
 * The caller supplies stable associated data to prevent a ciphertext from
 * being moved to another signature scope.
 */
class IpCipher
{
	const FORMAT = 'EIP1';
	const CIPHER = 'aes-256-gcm';
	const NONCE_LENGTH = 12;
	const TAG_LENGTH = 16;

	/** @var string Binary AES-256 key. */
	private $key;

	/**
	 * @param string $key Binary 32-byte key.
	 * @return void
	 */
	public function __construct($key)
	{
		if (!is_string($key) || strlen($key) !== 32) {
			throw new \InvalidArgumentException('IP encryption key must contain exactly 32 bytes.');
		}
		$this->key = $key;
	}

	/**
	 * @param string $ip Valid IPv4 or IPv6 address.
	 * @param string $associatedData Stable authenticated context.
	 * @return string Versioned, URL-safe ciphertext.
	 */
	public function encrypt($ip, $associatedData)
	{
		$this->assertAvailable();
		$this->assertIp($ip);
		if (!is_string($associatedData)) {
			throw new \InvalidArgumentException('IP encryption associated data must be a string.');
		}

		$nonce = random_bytes(self::NONCE_LENGTH);
		$tag = '';
		$ciphertext = openssl_encrypt(
			$ip,
			self::CIPHER,
			$this->key,
			OPENSSL_RAW_DATA,
			$nonce,
			$tag,
			$associatedData,
			self::TAG_LENGTH
		);
		if (!is_string($ciphertext) || strlen($tag) !== self::TAG_LENGTH) {
			throw new \RuntimeException('Could not encrypt the signature IP address.');
		}

		return self::FORMAT . '.' . Base64Url::encode($nonce) . '.' . Base64Url::encode($tag) . '.' . Base64Url::encode($ciphertext);
	}

	/**
	 * @param string $envelope Versioned, URL-safe ciphertext.
	 * @param string $associatedData Stable authenticated context.
	 * @return string Valid IPv4 or IPv6 address.
	 */
	public function decrypt($envelope, $associatedData)
	{
		$this->assertAvailable();
		if (!is_string($envelope) || !is_string($associatedData)) {
			throw new \InvalidArgumentException('IP ciphertext and associated data must be strings.');
		}
		$parts = explode('.', $envelope);
		if (count($parts) !== 4 || $parts[0] !== self::FORMAT) {
			throw new \UnexpectedValueException('Invalid signature IP ciphertext format.');
		}

		$nonce = Base64Url::decode($parts[1]);
		$tag = Base64Url::decode($parts[2]);
		$ciphertext = Base64Url::decode($parts[3]);
		if (strlen($nonce) !== self::NONCE_LENGTH || strlen($tag) !== self::TAG_LENGTH || $ciphertext === '') {
			throw new \UnexpectedValueException('Invalid signature IP ciphertext components.');
		}

		$ip = openssl_decrypt(
			$ciphertext,
			self::CIPHER,
			$this->key,
			OPENSSL_RAW_DATA,
			$nonce,
			$tag,
			$associatedData
		);
		if (!is_string($ip)) {
			throw new \UnexpectedValueException('Could not authenticate the signature IP ciphertext.');
		}
		$this->assertIp($ip);
		return $ip;
	}

	/** @return void */
	private function assertAvailable()
	{
		if (!function_exists('openssl_encrypt') || !function_exists('openssl_decrypt')) {
			throw new \RuntimeException('OpenSSL authenticated encryption is unavailable.');
		}
		$ciphers = array_map('strtolower', openssl_get_cipher_methods());
		if (!in_array(self::CIPHER, $ciphers, true)) {
			throw new \RuntimeException('AES-256-GCM is unavailable.');
		}
	}

	/**
	 * @param mixed $ip
	 * @return void
	 */
	private function assertIp($ip)
	{
		if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
			throw new \InvalidArgumentException('IP address is invalid.');
		}
	}
}
