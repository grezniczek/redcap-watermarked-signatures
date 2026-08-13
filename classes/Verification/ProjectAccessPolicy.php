<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Verification;

/**
 * Project UI authorization based on REDCap form rights and DAG membership.
 */
class ProjectAccessPolicy
{
	/** @var int */
	private $projectId;

	/** @var bool */
	private $superUser;

	/** @var array<string, mixed> REDCap user rights. */
	private $rights;

	/** @var callable(string): int|string|null|false Resolves a record ID to its DAG ID. */
	private $recordDagResolver;

	/**
	 * @param int $projectId
	 * @param bool $superUser
	 * @param array<string, mixed> $rights REDCap user rights.
	 * @param callable(string): int|string|null|false $recordDagResolver
	 * @return void
	 */
	public function __construct($projectId, $superUser, $rights, $recordDagResolver)
	{
		if (!is_int($projectId) || $projectId < 1) {
			throw new \InvalidArgumentException('Project ID must be a positive integer.');
		}
		if (!is_array($rights)) {
			throw new \InvalidArgumentException('Project rights must be an array.');
		}
		if (!is_callable($recordDagResolver)) {
			throw new \InvalidArgumentException('Record DAG resolver must be callable.');
		}
		$this->projectId = $projectId;
		$this->superUser = (bool) $superUser;
		$this->rights = $rights;
		$this->recordDagResolver = $recordDagResolver;
	}

	/**
	 * @param array<int, string> $instruments
	 * @return bool
	 */
	public function canAccessAnyInstrument($instruments)
	{
		foreach (array_unique($instruments) as $instrument) {
			if ($this->canViewInstrument($instrument)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string $instrument
	 * @return bool
	 */
	public function canViewInstrument($instrument)
	{
		if ($this->superUser) {
			return true;
		}
		if (!isset($this->rights['data_entry']) || !is_string($this->rights['data_entry'])) {
			return false;
		}

		$forms = \UserRights::convertFormRightsToArray($this->rights['data_entry']);
		$value = $forms[(string) $instrument] ?? null;
		return !\UserRights::hasDataViewingRights($value, 'no-access');
	}

	/**
	 * @param array<string, mixed> $upload
	 * @return bool
	 */
	public function canViewUpload($upload)
	{
		return is_array($upload)
			&& isset($upload['pid'], $upload['instrument'])
			&& (int) $upload['pid'] === $this->projectId
			&& $this->canViewInstrument($upload['instrument']);
	}

	/**
	 * @param array<string, mixed> $binding
	 * @return bool
	 */
	public function canViewBinding($binding)
	{
		if (!is_array($binding)
			|| !isset($binding['pid'], $binding['instrument'], $binding['record_id'])
			|| (int) $binding['pid'] !== $this->projectId
			|| !$this->canViewInstrument($binding['instrument'])) {
			return false;
		}
		if ($this->superUser || !$this->isDagRestricted()) {
			return true;
		}

		$recordDag = call_user_func($this->recordDagResolver, (string) $binding['record_id']);
		return $recordDag !== false
			&& $recordDag !== null
			&& (string) $recordDag === (string) $this->rights['group_id'];
	}

	/**
	 * @return bool
	 */
	public function isDagRestricted()
	{
		return !$this->superUser
			&& isset($this->rights['group_id'])
			&& $this->rights['group_id'] !== null
			&& $this->rights['group_id'] !== '';
	}
}
