<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Verification;

/**
 * Creates a normal REDCap data-entry URL for an already-authorized binding.
 */
class RedcapFieldLink
{
	/**
	 * @param array<string, mixed> $binding Already-authorized binding.
	 * @param scalar|null $currentRecordId
	 * @return string|null Data-entry URL, or null when the binding cannot form one.
	 */
	public static function create($binding, $currentRecordId)
	{
		if (!defined('APP_PATH_WEBROOT') || !is_array($binding)
			|| !is_numeric($binding['pid'] ?? null) || (int) $binding['pid'] < 1
			|| !is_numeric($binding['event_id'] ?? null) || (int) $binding['event_id'] < 1
			|| !is_string($binding['instrument'] ?? null) || $binding['instrument'] === ''
			|| !is_scalar($currentRecordId) || (string) $currentRecordId === '') {
			return null;
		}

		$parameters = array(
			'pid' => (int) $binding['pid'],
			'id' => (string) $currentRecordId,
			'event_id' => (int) $binding['event_id'],
			'page' => $binding['instrument'],
			'instance' => max(1, (int) ($binding['repeat_instance'] ?? 1))
		);

		return rtrim((string) APP_PATH_WEBROOT, '/')
			. '/DataEntry/index.php?'
			. http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
	}
}
