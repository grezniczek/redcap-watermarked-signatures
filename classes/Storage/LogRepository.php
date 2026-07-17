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

    private $module;
    private $bindingMac;

    public function __construct($module, BindingMac $bindingMac)
    {
        $this->module = $module;
        $this->bindingMac = $bindingMac;
    }

    public function findUploadByEdocId($edocId)
    {
        return $this->findEventByEdocId('sigwm_upload', $edocId);
    }

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

    public function findBindingByEdocId($edocId)
    {
        return $this->findEventByEdocId('sigwm_bind', $edocId);
    }

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

    private function findEventByEdocId($message, $edocId)
    {
        $result = $this->queryLogsPrimary(
            // Mentioning project_id explicitly suppresses the framework's
            // automatic current-project clause. The one-edoc-one-binding
            // invariant applies across every project using this module.
            'select log_id, payload_json, project_id where message = ? and edoc_id = ? and project_id >= 0 order by log_id asc limit 2',
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

    private function decodeEventRow($row, $message)
    {
        $payload = json_decode($row['payload_json'] ?? '', true);
        if (!is_array($payload) || json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException("The {$message} log payload is invalid.");
        }
        $payload['_log_id'] = (int) $row['log_id'];
        $payload['_project_id'] = isset($row['project_id']) ? (int) $row['project_id'] : null;
        return $payload;
    }

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

    private function queryLogsPrimary($pseudoSql, $parameters)
    {
        $hasPrimaryQuery = function_exists('db_query_throw_on_error') || function_exists('db_query');
        if ($hasPrimaryQuery && defined('MYSQLI_STORE_RESULT') && method_exists($this->module, 'getQueryLogsSql')) {
            $sql = $this->module->getQueryLogsSql($pseudoSql);
            return $this->queryPrimary($sql, $parameters);
        }
        return $this->module->queryLogs($pseudoSql, $parameters);
    }

    private function appendBinding($event)
    {
        $this->module->log('sigwm_bind', array(
            'record' => $event['record_id'],
            'anchor' => $event['anchor'],
            'capture_ref' => $event['capture_ref'],
            'context_ref' => $event['context_ref'],
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
