<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Context;

/**
 * Normalizes REDCap's classic, repeating-event, and repeating-form shapes.
 */
class SavedContext
{
    private $project;
    private $projectId;
    private $recordId;
    private $instrument;
    private $eventId;
    private $hookRepeatInstance;
    private $repeatType;

    public function __construct($project, $projectId, $recordId, $instrument, $eventId, $repeatInstance)
    {
        $this->project = $project;
        $this->projectId = (int) $projectId;
        $this->recordId = (string) $recordId;
        $this->instrument = (string) $instrument;
        $this->eventId = (int) $eventId;
        $this->hookRepeatInstance = max(1, (int) $repeatInstance);

        if ($project->isRepeatingEvent($this->eventId)) {
            $this->repeatType = 'event';
        } elseif ($project->isRepeatingForm($this->eventId, $this->instrument)) {
            $this->repeatType = 'instrument';
        } else {
            $this->repeatType = null;
        }
    }

    public function extractFieldValues($data, $fields)
    {
        $recordData = isset($data[$this->recordId]) ? $data[$this->recordId] : array();

        if ($this->repeatType === 'event') {
            $node = $recordData['repeat_instances'][$this->eventId][null][$this->hookRepeatInstance] ?? array();
        } elseif ($this->repeatType === 'instrument') {
            $node = $recordData['repeat_instances'][$this->eventId][$this->instrument][$this->hookRepeatInstance] ?? array();
        } else {
            $node = $recordData[$this->eventId] ?? array();
        }

        $values = array();
        foreach ($fields as $field) {
            $values[$field] = array_key_exists($field, $node) ? $node[$field] : null;
        }
        return $values;
    }

    public function bindingValues($field)
    {
        return array(
            'record_id' => $this->recordId,
            'pid' => $this->projectId,
            'event_id' => $this->eventId,
            'instrument' => $this->instrument,
            'field' => (string) $field,
            'repeat_type' => $this->repeatType,
            'repeat_instrument' => $this->repeatType === 'instrument' ? $this->instrument : null,
            'repeat_instance' => $this->repeatType === null ? null : $this->hookRepeatInstance
        );
    }
}
