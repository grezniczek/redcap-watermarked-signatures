<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Context;

/**
 * Normalizes REDCap's classic, repeating-event, and repeating-form shapes.
 */
class SavedContext
{
	/**
	 * REDCap's project metadata object.
	 *
	 * @var \Project
	 */
	private $project;

	/** @var int */
	private $projectId;

	/** @var string */
	private $recordId;

	/** @var string */
	private $instrument;

	/** @var int */
	private $eventId;

	/** @var int */
	private $hookRepeatInstance;

	/** @var 'event'|'instrument'|null */
	private $repeatType;

	/**
	 * @param \Project $project REDCap's project object. Compatible test doubles are also accepted at runtime.
	 * @param int|string $projectId
	 * @param scalar $recordId
	 * @param scalar $instrument
	 * @param int|string $eventId
	 * @param int|string|null $repeatInstance
	 * @return void
	 */
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

	/**
	 * Extract selected field values from REDCap's array-format getData result
	 * for this saved record, event, and optional repeat instance.
	 *
	 * @param array<string, mixed> $data
	 * @param array<int, string> $fields
	 * @return array<string, mixed>
	 */
	public function extractFieldValues($data, $fields)
	{
		$recordData = isset($data[$this->recordId]) ? $data[$this->recordId] : array();

		if ($this->repeatType === 'event') {
			// Records::getData() uses an empty repeat-instrument key for a
			// repeating event because the event itself owns the instance.
			$node = $recordData['repeat_instances'][$this->eventId][''][$this->hookRepeatInstance] ?? array();
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

	/**
	 * Return the normalized context used to bind a saved signature to its
	 * record location.
	 *
	 * @param scalar $field
	 * @return array{
	 *     record_id: string,
	 *     pid: int,
	 *     event_id: int,
	 *     instrument: string,
	 *     field: string,
	 *     repeat_type: 'event'|'instrument'|null,
	 *     repeat_instrument: string|null,
	 *     repeat_instance: int|null
	 * }
	 */
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
