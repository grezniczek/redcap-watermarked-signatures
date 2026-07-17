<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Verification;

/**
 * Reads the field location recorded in a verified binding.
 * Authorization is the responsibility of the calling UI/controller.
 */
class RedcapCurrentValueReader
{
    public function read($binding)
    {
        $data = \REDCap::getData(array(
            'project_id' => (int) $binding['pid'],
            'return_format' => 'array',
            'records' => array((string) $binding['record_id']),
            'fields' => array((string) $binding['field']),
            'events' => array((int) $binding['event_id'])
        ));
        if (!is_array($data)) {
            throw new \RuntimeException('REDCap did not return record data as an array.');
        }

        $record = (string) $binding['record_id'];
        $eventId = (int) $binding['event_id'];
        $instrument = (string) $binding['instrument'];
        $field = (string) $binding['field'];
        $recordData = isset($data[$record]) ? $data[$record] : array();

        if ($binding['repeat_type'] === 'event') {
            $instance = max(1, (int) $binding['repeat_instance']);
            $node = $recordData['repeat_instances'][$eventId][''][$instance] ?? array();
        } elseif ($binding['repeat_type'] === 'instrument') {
            $instance = max(1, (int) $binding['repeat_instance']);
            $node = $recordData['repeat_instances'][$eventId][$instrument][$instance] ?? array();
        } elseif ($binding['repeat_type'] === null) {
            $node = $recordData[$eventId] ?? array();
        } else {
            throw new \UnexpectedValueException('The binding contains an unsupported repeat type.');
        }

        return array_key_exists($field, $node) ? $node[$field] : null;
    }
}
