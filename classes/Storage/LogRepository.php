<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Storage;

use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\BindingMac;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\CanonicalJson;

/**
 * Append-only signature state stored in the External Module log.
 */
class LogRepository
{
	const RESULT_BOUND = 'bound';
	const RESULT_IDEMPOTENT = 'idempotent';
	const RESULT_CONFLICT = 'conflict';
	const RESULT_INVALID_EXISTING_MAC = 'invalid_existing_mac';
	const RESULT_ORIGIN_MISMATCH = 'origin_mismatch';
	const LOCK_TIMEOUT_SECONDS = 10;

	/** @var \DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule */
	private $module;

	/** @var BindingMac */
	private $bindingMac;

	/**
	 * @param \DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule $module
	 * @param BindingMac $bindingMac
	 * @return void
	 */
	public function __construct($module, BindingMac $bindingMac)
	{
		$this->module = $module;
		$this->bindingMac = $bindingMac;
	}

	/**
	 * @param int|string $edocId
	 * @return array<string, mixed>|null
	 */
	public function findUploadByEdocId($edocId)
	{
		return $this->findEventByEdocId('sigwm_upload', $edocId);
	}

	/**
	 * @param string $captureReference
	 * @param int|null $projectId Null permits an administrator lookup across projects.
	 * @return array<string, mixed>|null
	 */
	public function findUploadByCaptureReference($captureReference, $projectId = null)
	{
		$parameters = array('sigwm_upload', (string) $captureReference);
		if ($projectId === null) {
			// Mention project_id explicitly to permit an administrator lookup
			// across all projects using this module.
			$projectClause = 'project_id >= 0';
		} else {
			$projectClause = 'project_id = ?';
			$parameters[] = (int) $projectId;
		}

		$result = $this->queryLogsPrimary(
			"select log_id, payload_json, project_id where message = ? and capture_ref = ? and {$projectClause} order by log_id asc limit 2",
			$parameters
		);
		$row = $result ? $result->fetch_assoc() : null;
		if (!$row) {
			return null;
		}
		if ($result->fetch_assoc()) {
			throw new \RuntimeException('Multiple upload events have the same capture reference.');
		}

		$payload = $this->decodeEventRow($row, 'sigwm_upload');
		if (!isset($payload['capture_ref']) || !hash_equals((string) $captureReference, (string) $payload['capture_ref'])) {
			throw new \RuntimeException('The sigwm_upload log payload has a mismatched capture reference.');
		}
		return $payload;
	}

	/**
	 * @param int|string $edocId
	 * @return array<string, mixed>|null
	 */
	public function findBindingByEdocId($edocId)
	{
		return $this->findEventByEdocId('sigwm_bind', $edocId);
	}

	/**
	 * Return record-rename events associated with the current record ID. REDCap
	 * updates the indexed record column in all EM log rows during each rename,
	 * so this returns the retained rename history for a binding.
	 * 
	 * @param int|string $projectId
	 * @param scalar $recordId
	 * @return array<int, array<string, mixed>>
	 */
	public function findRecordRenameEventsByCurrentRecord($projectId, $recordId)
	{
		if (!is_numeric($projectId) || (int) $projectId < 1 || !is_scalar($recordId) || (string) $recordId === '') {
			return array();
		}

		$result = $this->queryLogsPrimary(
			'select log_id, timestamp, username, project_id, record, message, previous_record_id, rename_origin, rename_username, renamed_at where message = ? and project_id = ? and record = ? order by log_id asc',
			array('sigwm_record_rename', (int) $projectId, (string) $recordId)
		);
		$events = array();
		while ($result && ($row = $result->fetch_assoc())) {
			$events[] = $row;
		}
		return $events;
	}

	/**
	 * Return the persisted spelling of a record ID when this project has at
	 * least one module binding for it. REDCap updates the indexed `record`
	 * column when it renames a record, so this is also a safe post-rename
	 * existence check.
	 * 
	 * @param scalar $recordId
	 * @return string|null
	 */
	public function findBoundRecordId($recordId)
	{
		// This lookup immediately follows a REDCap record rename in two
		// supported paths. Route it to the primary so replica lag cannot make
		// a completed rename look absent and suppress its audit event.
		$result = $this->queryLogsPrimary(
			'select record where message = ? and record = ? order by log_id asc limit 1',
			array('sigwm_bind', (string) $recordId)
		);
		$row = $result ? $result->fetch_assoc() : null;
		if (!$row || !isset($row['record']) || $row['record'] === '') {
			return null;
		}
		return (string) $row['record'];
	}

	/**
	 * Remove only expired upload events that never obtained a binding. The
	 * caller must have selected the target project in the EM framework.
	 * @param string $beforeTimestamp Database timestamp cutoff.
	 * @return int Number of removed upload events.
	 */
	public function purgeExpiredUnboundUploads($beforeTimestamp)
	{
		$result = $this->module->queryLogs(
			'select log_id, edoc_id where message = ? and timestamp < ? order by log_id asc',
			array('sigwm_upload', (string) $beforeTimestamp)
		);
		$removed = 0;

		while ($result && ($row = $result->fetch_assoc())) {
			$logId = isset($row['log_id']) ? (int) $row['log_id'] : 0;
			$edocId = isset($row['edoc_id']) ? (int) $row['edoc_id'] : 0;
			if ($logId < 1 || $edocId < 1) {
				// A malformed provenance entry is evidence worth retaining;
				// it must not be silently deleted by routine cleanup.
				continue;
			}

			// A binding can be in a different project only in an invalid
			// cross-project edoc reuse attempt. Check globally so cleanup
			// remains conservative in that situation too.
			if ($this->findBindingByEdocId($edocId) !== null) {
				continue;
			}

			$removed += (int) $this->module->removeLogs(
				'log_id = ? and message = ?',
				array($logId, 'sigwm_upload')
			);
		}

		return $removed;
	}

	/**
	 * Reserve a signed no-auth capture envelope exactly once. The nonce itself
	 * is never persisted; its SHA-256 digest is enough for replay detection.
	 * The named lock makes the lookup-and-insert sequence safe across
	 * concurrent upload requests and database replicas.
	 * 
	 * @param string $nonce Base64url envelope nonce.
	 * @return bool False if the nonce was already reserved.
	 */
	public function reserveEnvelopeNonce($nonce)
	{
		if (!is_string($nonce) || !preg_match('/^[A-Za-z0-9_-]{20,64}$/', $nonce)) {
			throw new \InvalidArgumentException('The signature envelope nonce is invalid.');
		}

		$nonceHash = hash('sha256', $nonce);
		// MySQL named locks are limited to 64 characters.
		$lockName = 'sigwm:nonce:' . substr($nonceHash, 0, 48);
		$lockResult = $this->queryPrimary('SELECT GET_LOCK(?, ?)', array($lockName, self::LOCK_TIMEOUT_SECONDS));
		$lockRow = $lockResult ? $lockResult->fetch_row() : null;

		if ((int) ($lockRow[0] ?? 0) !== 1) {
			throw new \RuntimeException('Timed out while acquiring the signature envelope lock.');
		}

		try {
			$result = $this->queryLogsPrimary(
				// Envelope nonces are random installation-wide values. Query
				// every project so a collision cannot weaken the one-time
				// use invariant.
				'select log_id where message = ? and envelope_nonce_hash = ? and project_id >= 0 order by log_id asc limit 1',
				array('sigwm_envelope_nonce', $nonceHash)
			);
			if ($result && $result->fetch_assoc()) {
				return false;
			}

			$this->module->log('sigwm_envelope_nonce', array(
				'envelope_nonce_hash' => $nonceHash
			));
			return true;
		} finally {
			$this->queryPrimary('SELECT RELEASE_LOCK(?)', array($lockName));
		}
	}

	/**
	 * Remove expired replay guards. A reservation is retained past the
	 * maximum allowed envelope lifetime, including permitted clock skew.
	 * 
	 * @param string $beforeTimestamp Database timestamp cutoff.
	 * @return int Number of removed nonce reservations.
	 */
	public function purgeExpiredEnvelopeNonces($beforeTimestamp)
	{
		$result = $this->module->queryLogs(
			'select log_id where message = ? and timestamp < ? order by log_id asc',
			array('sigwm_envelope_nonce', (string) $beforeTimestamp)
		);
		$removed = 0;

		while ($result && ($row = $result->fetch_assoc())) {
			$logId = isset($row['log_id']) ? (int) $row['log_id'] : 0;
			if ($logId < 1) {
				continue;
			}
			$removed += (int) $this->module->removeLogs(
				'log_id = ? and message = ?',
				array($logId, 'sigwm_envelope_nonce')
			);
		}

		return $removed;
	}

	/**
	 * @param array{v: int, pid: int, new_record_id: string, old_record_id: string, rename_origin: string, rename_username: string|null, renamed_at: string} $event
	 * @return void
	 */
	public function appendRecordRename($event)
	{
		$this->module->log('sigwm_record_rename', array(
			'record' => $event['new_record_id'],
			'previous_record_id' => $event['old_record_id'],
			'rename_origin' => $event['rename_origin'],
			'rename_username' => $event['rename_username'],
			'renamed_at' => $event['renamed_at'],
			'payload_json' => CanonicalJson::encode($event)
		));
	}

	/**
	 * Return the technical log history associated with one globally unique edoc.
	 * The administrator presenter selects the fields it may expose.
	 * 
	 * @param int|string $edocId
	 * @return array<int, array<string, mixed>>
	 */
	public function findDiagnosticEventsByEdocId($edocId)
	{
		$edocId = (int) $edocId;
		if ($edocId < 1) {
			return array();
		}

		$result = $this->queryLogsPrimary(
			'select log_id, timestamp, username, project_id, record, message, edoc_id, capture_ref, context_ref, project_reference, anchor, event_id, instrument, field, capture_origin, capture_username, save_origin, save_username, bound_at, technical_message, original_log_id, binding_log_id where edoc_id = ? and project_id >= 0 order by log_id asc',
			array($edocId)
		);
		$events = array();
		while ($result && ($row = $result->fetch_assoc())) {
			$events[] = $row;
		}
		return $events;
	}

	/**
	 * @param array<string, mixed> $binding Authoritative saved-signature binding.
	 * @return 'bound'|'idempotent'|'conflict'|'invalid_existing_mac'|'origin_mismatch'
	 */
	public function bindOnce($binding)
	{
		$edocId = (int) $binding['edoc_id'];
		// Edoc IDs are globally unique in REDCap, so the lock must not be
		// project-scoped. This serializes cross-project reuse attempts too.
		$lockName = 'sigwm:bind:' . $edocId;
		$lockResult = $this->queryPrimary('SELECT GET_LOCK(?, ?)', array($lockName, self::LOCK_TIMEOUT_SECONDS));
		$lockRow = $lockResult ? $lockResult->fetch_row() : null;

		if ((int) ($lockRow[0] ?? 0) !== 1) {
			throw new \RuntimeException('Timed out while acquiring the signature binding lock.');
		}

		try {
			// Query again only after acquiring the per-edoc lock.
			$existing = $this->findBindingByEdocId($edocId);
			if ($existing === null) {
				if ($binding['capture_origin'] !== $binding['save_origin']) {
					$this->appendOriginMismatch($binding);
					return self::RESULT_ORIGIN_MISMATCH;
				}
				$event = $binding;
				$event['binding_mac'] = $this->bindingMac->create($event);
				$this->appendBinding($event);
				return self::RESULT_BOUND;
			}

			if (!$this->bindingMac->verify($existing)) {
				$this->appendBindingMacError($existing, $binding);
				return self::RESULT_INVALID_EXISTING_MAC;
			}

			if ($this->bindingMac->equals($existing, $binding)) {
				return self::RESULT_IDEMPOTENT;
			}

			$this->appendConflict($existing, $binding);
			return self::RESULT_CONFLICT;
		} finally {
			$this->queryPrimary('SELECT RELEASE_LOCK(?)', array($lockName));
		}
	}

	/**
	 * @param string $message EM log message name.
	 * @param int|string $edocId
	 * @return array<string, mixed>|null
	 */
	private function findEventByEdocId($message, $edocId)
	{
		$result = $this->queryLogsPrimary(
			// Mentioning project_id explicitly suppresses the framework's
			// automatic current-project clause. The one-edoc-one-binding
			// invariant applies across every project using this module.
			'select log_id, payload_json, project_id, record where message = ? and edoc_id = ? and project_id >= 0 order by log_id asc limit 2',
			array($message, (int) $edocId)
		);
		$row = $result ? $result->fetch_assoc() : null;
		if (!$row) {
			return null;
		}
		if ($result->fetch_assoc()) {
			throw new \RuntimeException("Multiple {$message} events have the same edoc ID.");
		}

		$payload = $this->decodeEventRow($row, $message);
		if (!isset($payload['edoc_id']) || (int) $payload['edoc_id'] !== (int) $edocId) {
			throw new \RuntimeException("The {$message} log payload has a mismatched edoc ID.");
		}
		return $payload;
	}

	/**
	 * @param array<string, mixed> $row EM log database row.
	 * @param string $message Expected EM log message name.
	 * @return array<string, mixed>
	 */
	private function decodeEventRow($row, $message)
	{
		$payload = json_decode($row['payload_json'] ?? '', true);
		if (!is_array($payload) || json_last_error() !== JSON_ERROR_NONE) {
			throw new \RuntimeException("The {$message} log payload is invalid.");
		}
		$payload['_log_id'] = (int) $row['log_id'];
		$payload['_project_id'] = isset($row['project_id']) ? (int) $row['project_id'] : null;
		$payload['_current_record_id'] = isset($row['record']) && $row['record'] !== null && $row['record'] !== ''
			? (string) $row['record']
			: null;
		return $payload;
	}

	/**
	 * @param string $sql
	 * @param array<int, mixed> $parameters
	 * @return \mysqli_result|bool
	 */
	private function queryPrimary($sql, $parameters)
	{
		// REDCap may route SELECT statements to a read replica. Named locks and
		// their protected reads must use the primary connection or replica lag
		// could allow a duplicate binding to be inserted on the primary.
		if (function_exists('db_query_throw_on_error') && defined('MYSQLI_STORE_RESULT')) {
			return \db_query_throw_on_error($sql, $parameters, null, MYSQLI_STORE_RESULT, true);
		}
		if (function_exists('db_query') && defined('MYSQLI_STORE_RESULT')) {
			return \db_query($sql, $parameters, null, MYSQLI_STORE_RESULT, true);
		}
		return $this->module->query($sql, $parameters);
	}

	/**
	 * @param string $pseudoSql External Module log-query SQL.
	 * @param array<int, mixed> $parameters
	 * @return \mysqli_result|bool
	 */
	private function queryLogsPrimary($pseudoSql, $parameters)
	{
		$hasPrimaryQuery = function_exists('db_query_throw_on_error') || function_exists('db_query');
		if ($hasPrimaryQuery && defined('MYSQLI_STORE_RESULT') && method_exists($this->module, 'getQueryLogsSql')) {
			$sql = $this->module->getQueryLogsSql($pseudoSql);
			return $this->queryPrimary($sql, $parameters);
		}
		return $this->module->queryLogs($pseudoSql, $parameters);
	}

	/**
	 * @param array<string, mixed> $event Binding with its computed binding_mac.
	 * @return void
	 */
	private function appendBinding($event)
	{
		$this->module->log('sigwm_bind', array(
			'record' => $event['record_id'],
			'anchor' => $event['anchor'],
			'capture_ref' => $event['capture_ref'],
			'context_ref' => $event['context_ref'],
			'project_reference' => $event['project_reference'],
			'capture_origin' => $event['capture_origin'],
			'capture_username' => $event['capture_username'],
			'save_origin' => $event['save_origin'],
			'save_username' => $event['save_username'],
			'event_id' => $event['event_id'],
			'instrument' => $event['instrument'],
			'field' => $event['field'],
			'edoc_id' => $event['edoc_id'],
			'binding_mac' => $event['binding_mac'],
			'bound_at' => $event['bound_at'],
			'payload_json' => CanonicalJson::encode($event)
		));
	}

	/**
	 * @param array<string, mixed> $attempted Attempted authoritative binding.
	 * @return void
	 */
	private function appendOriginMismatch($attempted)
	{
		$this->module->log('sigwm_error_origin_mismatch', array(
			'record' => $attempted['record_id'],
			'edoc_id' => $attempted['edoc_id'],
			'capture_origin' => $attempted['capture_origin'],
			'capture_username' => $attempted['capture_username'],
			'save_origin' => $attempted['save_origin'],
			'save_username' => $attempted['save_username'],
			'technical_message' => 'Signature capture and first-save origins do not match.',
			'payload_json' => CanonicalJson::encode($attempted)
		));
	}

	/**
	 * @param array<string, mixed> $existing Existing authoritative binding.
	 * @param array<string, mixed> $attempted Attempted authoritative binding.
	 * @return void
	 */
	private function appendConflict($existing, $attempted)
	{
		$this->module->log('sigwm_error_edoc_already_bound', array(
			'record' => $attempted['record_id'],
			'edoc_id' => $attempted['edoc_id'],
			'original_log_id' => $existing['_log_id'] ?? '',
			'original_binding_json' => CanonicalJson::encode($existing),
			'attempted_binding_json' => CanonicalJson::encode($attempted)
		));
	}

	/**
	 * @param array<string, mixed> $existing Existing binding with an invalid MAC.
	 * @param array<string, mixed> $attempted Attempted authoritative binding.
	 * @return void
	 */
	private function appendBindingMacError($existing, $attempted)
	{
		$this->module->log('sigwm_error_binding_mac', array(
			'record' => $attempted['record_id'],
			'edoc_id' => $attempted['edoc_id'],
			'binding_log_id' => $existing['_log_id'] ?? '',
			'attempted_binding_json' => CanonicalJson::encode($attempted)
		));
	}
}
