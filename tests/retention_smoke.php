<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Tests;

require_once __DIR__ . '/../classes/Crypto/CanonicalJson.php';
require_once __DIR__ . '/../classes/Crypto/BindingMac.php';
require_once __DIR__ . '/../classes/Storage/LogRepository.php';

use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\BindingMac;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\CanonicalJson;
use DE\RUB\WatermarkedSignaturesExternalModule\Storage\LogRepository;
use RuntimeException;

function retentionAssert($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

class RetentionResult
{
    private $rows;

    public function __construct($rows)
    {
        $this->rows = array_values($rows);
    }

    public function fetch_assoc()
    {
        return empty($this->rows) ? null : array_shift($this->rows);
    }
}

class RetentionModule
{
    public $events = array();

    public function addEvent($message, $edocId, $timestamp)
    {
        $this->events[] = array(
            'log_id' => count($this->events) + 1,
            'message' => $message,
            'edoc_id' => $edocId,
            'timestamp' => $timestamp,
            'payload_json' => CanonicalJson::encode(array('edoc_id' => $edocId))
        );
    }

    public function queryLogs($sql, $parameters)
    {
        if (strpos($sql, 'timestamp < ?') !== false) {
            list($message, $cutoff) = $parameters;
            $rows = array();
            foreach ($this->events as $event) {
                if ($event['message'] === $message && $event['timestamp'] < $cutoff) {
                    $rows[] = array(
                        'log_id' => $event['log_id'],
                        'edoc_id' => $event['edoc_id']
                    );
                }
            }
            return new RetentionResult($rows);
        }

        list($message, $edocId) = $parameters;
        $rows = array();
        foreach ($this->events as $event) {
            if ($event['message'] === $message && (int) $event['edoc_id'] === (int) $edocId) {
                $rows[] = array(
                    'log_id' => $event['log_id'],
                    'payload_json' => $event['payload_json'],
                    'project_id' => 123
                );
            }
        }
        return new RetentionResult(array_slice($rows, 0, 2));
    }

    public function removeLogs($sql, $parameters)
    {
        list($logId, $message) = $parameters;
        $before = count($this->events);
        $this->events = array_values(array_filter($this->events, function ($event) use ($logId, $message) {
            return !((int) $event['log_id'] === (int) $logId && $event['message'] === $message);
        }));
        return $before - count($this->events);
    }
}

$config = json_decode(file_get_contents(__DIR__ . '/../config.json'), true);
retentionAssert(is_array($config), 'config.json is invalid.');
$retentionSetting = null;
foreach ($config['project-settings'] as $setting) {
    if (($setting['key'] ?? null) === 'unbound-upload-retention-days') {
        $retentionSetting = $setting;
        break;
    }
}
retentionAssert(($retentionSetting['default'] ?? null) === '90', 'Unbound-upload retention must default to 90 days.');
retentionAssert(($retentionSetting['type'] ?? null) === 'text', 'Unbound-upload retention must be a project setting.');
retentionAssert(($config['crons'][0]['method'] ?? null) === 'cron_purge_unbound_upload_provenance', 'Retention cleanup cron is not registered.');

$module = new RetentionModule();
$module->addEvent('sigwm_upload', 1001, '2026-01-01 00:00:00');
$module->addEvent('sigwm_upload', 1002, '2026-01-01 00:00:00');
$module->addEvent('sigwm_bind', 1002, '2026-01-01 00:01:00');
$module->addEvent('sigwm_upload', 1003, '2026-07-16 00:00:00');
$module->addEvent('sigwm_upload', 0, '2026-01-01 00:00:00');

$repository = new LogRepository($module, new BindingMac(str_repeat('a', 32)));
$removed = $repository->purgeExpiredUnboundUploads('2026-04-18 00:00:00');
retentionAssert($removed === 1, 'Exactly one expired, unbound upload should be purged.');

$remaining = array();
foreach ($module->events as $event) {
    $remaining[] = $event['message'] . ':' . $event['edoc_id'];
}
retentionAssert(!in_array('sigwm_upload:1001', $remaining, true), 'Expired unbound upload was retained.');
retentionAssert(in_array('sigwm_upload:1002', $remaining, true), 'Bound upload provenance was purged.');
retentionAssert(in_array('sigwm_upload:1003', $remaining, true), 'Recent upload provenance was purged.');
retentionAssert(in_array('sigwm_upload:0', $remaining, true), 'Malformed upload provenance was purged.');

echo "Retention smoke test passed.\n";
