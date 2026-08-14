<?php

/** @var \DE\RUB\WatermarkedSignaturesExternalModule\WatermarkedSignaturesExternalModule $module */

if (!isset($actionTagAudit) || !is_array($actionTagAudit) || empty($actionTagAudit)) {
	return;
}

$auditEscape = function ($value) {
	return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
};
$auditHeading = $module->framework->tt('ui_action_tag_audit_heading'); // Watermarked Signatures action-tag audit
$auditIntro = $module->framework->tt('ui_action_tag_audit_intro'); // The module checked every @WATERMARKED-SIGNATURE annotation in this project.
$auditReview = $module->framework->tt('ui_action_tag_audit_review'); // Correct these issues before relying on a field reference in REF:.
$auditIssueMessage = function ($issue) use ($module) {
	$code = $issue['code'] ?? '';
	$referenceValue = $issue['reference_value'] ?? '';
	$referenceLength = $issue['reference_length'] ?? '';
	$maximumLength = $issue['maximum_length'] ?? '';

	switch ($code) {
		case 'action_tag_unsupported_field':
			return $module->framework->tt('ui_action_tag_audit_unsupported_field'); // The tag only works on Signature and Enhanced Signature fields.
		case 'field_reference_parameter_format':
			return $module->framework->tt('ui_action_tag_audit_parameter_format'); // The parameter must be a simple double-quoted string.
		case 'field_reference_empty':
			return $module->framework->tt('ui_action_tag_audit_empty_reference'); // The field reference is empty after surrounding whitespace is removed.
		case 'field_reference_too_long':
			return $module->framework->tt('ui_action_tag_audit_reference_too_long', array(
				'reference_value' => $referenceValue,
				'reference_length' => $referenceLength,
				'maximum_length' => $maximumLength
			)); // Field reference {reference_value} has {reference_length} characters; the maximum is {maximum_length}.
		case 'field_reference_invalid_start':
			return $module->framework->tt('ui_action_tag_audit_invalid_start'); // The field reference must start with an ASCII letter or digit.
		case 'field_reference_invalid_characters':
			return $module->framework->tt('ui_action_tag_audit_invalid_characters'); // The field reference may contain only permitted ASCII characters.
		case 'multiple_action_tags':
			return $module->framework->tt('ui_action_tag_audit_multiple_tags'); // More than one @WATERMARKED-SIGNATURE tag is configured for this field.
		case 'project_reference_too_long':
			return $module->framework->tt('ui_action_tag_audit_project_reference_too_long', array(
				'reference_length' => $referenceLength,
				'maximum_length' => $maximumLength
			)); // The public project reference has {reference_length} characters and must be {maximum_length} or fewer to combine with a field reference.
		default:
			return $module->framework->tt('ui_action_tag_audit_invalid_reference'); // The field reference is invalid and will be omitted from REF:.
	}
};
?>

<section class="alert alert-warning mb-3" aria-labelledby="sigwm-action-tag-audit-heading">
	<div id="sigwm-action-tag-audit-heading" class="fw-bold mb-1"><i class="fa-solid fa-triangle-exclamation me-1"></i><?= $auditEscape($auditHeading) ?></div>
	<p class="mb-1"><?= $auditEscape($auditIntro) ?></p>
	<ul class="mb-1 ps-3">
		<?php foreach ($actionTagAudit as $issue): ?>
			<?php if (!is_array($issue)) continue; ?>
			<li>
				<code><?= $auditEscape($issue['field'] ?? '') ?></code>
				<?php if (($issue['instrument'] ?? '') !== ''): ?>
					<span class="text-muted">(<?= $auditEscape($issue['instrument']) ?>)</span>
				<?php endif; ?>
				&mdash; <?= $auditIssueMessage($issue) ?>
			</li>
		<?php endforeach; ?>
	</ul>
	<p class="mb-0"><?= $auditEscape($auditReview) ?></p>
</section>
