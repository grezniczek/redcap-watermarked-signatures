<?php

/** @var \DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule $module */

if (!isset($actionTagAudit) || !is_array($actionTagAudit) || empty($actionTagAudit)) {
	return;
}

$auditEscape = function ($value) {
	return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
};
$auditHeading = $module->framework->tt('ui_action_tag_audit_heading'); // Watermarked Signatures action-tag audit
$auditIntro = ($actionTagAuditScope ?? 'project') === 'instrument'
	? $module->framework->tt('ui_action_tag_audit_intro_instrument') // The module checked every @WATERMARKED-SIGNATURE annotation on this instrument.
	: $module->framework->tt('ui_action_tag_audit_intro'); // The module checked every @WATERMARKED-SIGNATURE annotation in this project.
$auditReview = $module->framework->tt('ui_action_tag_audit_review'); // Correct these issues before relying on a field reference in REF:.
$auditParameterValue = $module->framework->tt('ui_action_tag_audit_parameter_value'); // Parameter value:
$actionTagAuditFieldLinks = !empty($actionTagAuditFieldLinks);

/**
 * Render the exact parameter with every offending character emphasized.
 * The value comes from project metadata, so each individual character is
 * escaped before fixed, trusted markup is added around it.
 *
 * @param array<string,mixed> $issue
 * @return string
 */
$auditReferenceValue = function ($issue) use ($auditEscape) {
	if (!array_key_exists('reference_value', $issue) || $issue['reference_value'] === null) {
		return '';
	}

	$invalidPositions = array();
	foreach (($issue['diagnostics'] ?? array()) as $diagnostic) {
		if (!is_array($diagnostic)) {
			continue;
		}
		foreach (($diagnostic['positions'] ?? array()) as $position) {
			if (is_int($position) && $position > 0) {
				$invalidPositions[$position] = true;
			}
		}
	}

	$characters = preg_split('//u', (string) $issue['reference_value'], -1, PREG_SPLIT_NO_EMPTY);
	if (!is_array($characters)) {
		$characters = str_split((string) $issue['reference_value']);
	}
	$rendered = '';
	foreach ($characters as $index => $character) {
		$escapedCharacter = $auditEscape($character);
		$rendered .= isset($invalidPositions[$index + 1])
			? '<strong class="text-danger fw-bold">' . $escapedCharacter . '</strong>'
			: $escapedCharacter;
	}

	return '<code class="sigwm-action-tag-audit-reference" style="white-space: pre-wrap;">' . $rendered . '</code>';
};

/**
 * @param array<string,mixed> $issue
 * @return array<int,array{message:string,emphasize:bool}>
 */
$auditIssueMessages = function ($issue) use ($module) {
	$diagnostics = is_array($issue['diagnostics'] ?? null) ? $issue['diagnostics'] : array();
	if (empty($diagnostics) && ($issue['code'] ?? '') !== '') {
		$diagnostics = array(array(
			'code' => $issue['code'],
			'positions' => array(),
			'maximum_length' => $issue['maximum_length'] ?? null
		));
	}

	$messages = array();
	foreach ($diagnostics as $diagnostic) {
		if (!is_array($diagnostic)) {
			continue;
		}
		$code = $diagnostic['code'] ?? '';
		$positions = array_values(array_filter(
			$diagnostic['positions'] ?? array(),
			function ($position) { return is_int($position) && $position > 0; }
		));
		$positionList = implode(', ', $positions);
		$maximumLength = $diagnostic['maximum_length'] ?? ($issue['maximum_length'] ?? '');
		switch ($code) {
			case 'action_tag_unsupported_field':
				$messages[] = array('message' => $module->framework->tt('ui_action_tag_audit_unsupported_field'), 'emphasize' => false); // The tag only works on Signature and Enhanced Signature fields.
				break;
			case 'field_reference_parameter_format':
				$messages[] = array('message' => $module->framework->tt('ui_action_tag_audit_parameter_format'), 'emphasize' => false); // The parameter must be a simple double-quoted string.
				break;
			case 'field_reference_empty':
				$messages[] = array('message' => $module->framework->tt('ui_action_tag_audit_empty_reference'), 'emphasize' => false); // The field reference is empty after surrounding whitespace is removed.
				break;
			case 'field_reference_too_long':
				$messages[] = array('message' => $module->framework->tt('ui_action_tag_audit_reference_too_long', array(
					'reference_length' => $issue['reference_length'] ?? '',
					'maximum_length' => $maximumLength
				)), 'emphasize' => true); // The field reference exceeds the permitted length.
				break;
			case 'field_reference_invalid_start':
				$messages[] = array('message' => $module->framework->tt('ui_action_tag_audit_invalid_start', array(
					'positions' => $positionList
				)), 'emphasize' => true); // The field reference must start with an ASCII letter or digit.
				break;
			case 'field_reference_invalid_characters':
				$messages[] = array('message' => $module->framework->tt('ui_action_tag_audit_invalid_characters', array(
					'positions' => $positionList
				)), 'emphasize' => true); // Invalid characters are identified by position.
				break;
			case 'multiple_action_tags':
				$messages[] = array('message' => $module->framework->tt('ui_action_tag_audit_multiple_tags'), 'emphasize' => false); // More than one @WATERMARKED-SIGNATURE tag is configured for this field.
				break;
			case 'project_reference_too_long':
				$messages[] = array('message' => $module->framework->tt('ui_action_tag_audit_project_reference_too_long', array(
					'reference_length' => $issue['reference_length'] ?? '',
					'maximum_length' => $maximumLength
				)), 'emphasize' => true); // The public project reference cannot be combined with a field reference.
				break;
			default:
				$messages[] = array('message' => $module->framework->tt('ui_action_tag_audit_invalid_reference'), 'emphasize' => false); // The field reference is invalid and will be omitted from REF:.
				break;
		}
	}
	return $messages;
};
?>

<style>.sigwm-action-tag-audit code { color: #000; }</style>
<section class="sigwm-action-tag-audit alert alert-warning mb-3" aria-labelledby="sigwm-action-tag-audit-heading">
	<div id="sigwm-action-tag-audit-heading" class="fw-bold mb-1"><i class="fa-solid fa-triangle-exclamation me-1"></i><?= $auditEscape($auditHeading) ?></div>
	<p class="mb-1"><?= $auditEscape($auditIntro) ?></p>
	<ul class="mb-1 ps-3">
		<?php foreach ($actionTagAudit as $issue): ?>
			<?php if (!is_array($issue)) continue; ?>
			<li class="mb-1">
				<?php if ($actionTagAuditFieldLinks && ($issue['field'] ?? '') !== ''): ?>
					<a href="#design-<?= rawurlencode((string) $issue['field']) ?>"><code><?= $auditEscape($issue['field']) ?></code></a>
				<?php else: ?>
					<code><?= $auditEscape($issue['field'] ?? '') ?></code>
				<?php endif; ?>
				<?php if (($issue['instrument'] ?? '') !== ''): ?>
					<span class="text-muted">(<?= $auditEscape($issue['instrument']) ?>)</span>
				<?php endif; ?>
				<?php $referenceValue = $auditReferenceValue($issue); ?>
				<?php if ($referenceValue !== ''): ?>
					<div class="ms-1"><span class="text-muted"><?= $auditEscape($auditParameterValue) ?></span> <?= $referenceValue ?></div>
				<?php endif; ?>
				<?php foreach ($auditIssueMessages($issue) as $message): ?>
					<div class="ms-1<?= $message['emphasize'] ? ' text-danger fw-bold' : '' ?>"><?= $auditEscape($message['message']) ?></div>
				<?php endforeach; ?>
			</li>
		<?php endforeach; ?>
	</ul>
	<p class="mb-0"><?= $auditEscape($auditReview) ?></p>
</section>
