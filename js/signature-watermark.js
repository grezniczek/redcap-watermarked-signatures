(function (window, $) {
    'use strict';

    const config = window.REDCapSignatureWatermark;
    if (!config || config.installed || typeof window.filePopUp !== 'function') {
        return;
    }

    config.installed = true;
    const originalFilePopUp = window.filePopUp;

    window.filePopUp = function (fieldName, signatureType, replaceVersion) {
        const result = originalFilePopUp.apply(this, arguments);
        const envelope = config.envelopes && config.envelopes[fieldName];
        const form = document.getElementById('form_file_upload');
        let input = form && form.querySelector('input[name="sigwm_envelope"]');

        if (form && envelope && Number(signatureType) !== 0) {
            if (!input) {
                input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'sigwm_envelope';
                form.appendChild(input);
            }
            input.value = envelope;
        } else if (input) {
            // Never allow an envelope from a previously opened signature field
            // to accompany another field's upload if REDCap reuses the form.
            input.remove();
        }

        if (config.debug && window.console) {
            console.debug('[Watermarked Signatures] Prepared upload field', fieldName, Boolean(envelope));
        }

        return result;
    };
})(window, window.jQuery);
