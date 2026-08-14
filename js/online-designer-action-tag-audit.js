(function () {
	'use strict';

	function placeActionTagAudit() {
		var audit = document.getElementById('sigwm-online-designer-action-tag-audit');
		if (!audit) {
			return;
		}

		var fieldContainer = document.getElementById('draggablecontainer_parent');
		if (fieldContainer && fieldContainer.parentNode) {
			audit.style.maxWidth = '800px';
			fieldContainer.parentNode.insertBefore(audit, fieldContainer);
		} else {
			var formsSurveys = document.getElementById('forms_surveys');
			if (formsSurveys && formsSurveys.parentNode) {
				audit.style.maxWidth = '1040px';
				formsSurveys.parentNode.insertBefore(audit, formsSurveys);
			}
		}

		audit.hidden = false;
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', placeActionTagAudit);
	} else {
		placeActionTagAudit();
	}
}());
