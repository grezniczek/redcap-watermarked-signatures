(function (window, document) {
    'use strict';

    const validationDelayMilliseconds = 350;
    const previewMaximumWidth = 280;
    const previewMaximumHeight = 136;

    function init(module, config) {
        const form = document.getElementById('sigwm-project-settings-form');
        const imageInput = document.getElementById('sigwm-custom-image');
        const previewArea = document.getElementById('sigwm-custom-image-preview-area');
        const previewImage = document.getElementById('sigwm-custom-image-preview');
        const previewEmpty = document.getElementById('sigwm-custom-image-preview-empty');
        const rotation = document.getElementById('sigwm-background-rotation');
        const rotationOutput = document.getElementById('sigwm-background-rotation-output');
        const unsavedIndicator = document.getElementById('sigwm-settings-unsaved');
        const discardButton = document.getElementById('sigwm-settings-discard');
        const actionMessage = document.getElementById('sigwm-settings-action-message');

        if (!form || !imageInput || !previewArea || !previewImage || !previewEmpty || !rotation || !rotationOutput || !unsavedIndicator || !discardButton || !actionMessage || !module) {
            return;
        }

        let validationTimer = null;
        let validationSequence = 0;
        let allowNavigation = false;
        const debugLogger = typeof ConsoleDebugLogger === 'undefined' ? null : ConsoleDebugLogger;
        const logger = debugLogger
            ? debugLogger.create({ name: 'Watermarked Signatures project settings', active: Boolean(config.debug) })
            : { log: function () {}, warn: function () {} };

        const translate = function (key) {
            return module.tt(key);
        };

        const savedValues = config.savedValues || {};
        const getSelectedBackgroundMode = function () {
            const selected = form.querySelector('input[name="background_image_mode"]:checked');
            return selected ? selected.value : '';
        };
        const getCurrentValues = function () {
            return {
                retention_days: document.getElementById('sigwm-retention-days').value,
                public_project_reference: document.getElementById('sigwm-public-reference').value,
                background_image_mode: getSelectedBackgroundMode(),
                background_image_rotation: rotation.value
            };
        };
        const hasPendingCustomImage = function () {
            return Boolean(imageInput.files && imageInput.files.length);
        };
        const hasUnsavedChanges = function () {
            const currentValues = getCurrentValues();
            return hasPendingCustomImage()
                || Object.keys(currentValues).some(function (key) {
                    return String(currentValues[key]) !== String(savedValues[key] || '');
                });
        };
        const updateDirtyState = function () {
            const isDirty = hasUnsavedChanges();
            unsavedIndicator.hidden = !isDirty;
            discardButton.disabled = !isDirty;
            return isDirty;
        };

        const setActionMessage = function (messageKey) {
            if (!messageKey) {
                actionMessage.textContent = '';
                actionMessage.hidden = true;
                return;
            }
            actionMessage.textContent = translate(messageKey);
            actionMessage.hidden = false;
        };
        const setFieldError = function (field, errorKey) {
            const fieldContainer = form.querySelector('[data-settings-field="' + field + '"]');
            const errorOutput = form.querySelector('[data-settings-error="' + field + '"]');
            if (!fieldContainer || !errorOutput) {
                return;
            }
            const controls = fieldContainer.querySelectorAll('input');
            controls.forEach(function (control) {
                control.classList.toggle('is-invalid', Boolean(errorKey));
            });
            if (errorKey) {
                errorOutput.textContent = translate(errorKey);
                errorOutput.hidden = false;
            } else {
                errorOutput.textContent = '';
                errorOutput.hidden = true;
            }
        };
        const showValidationErrors = function (errors) {
            const fields = [
                'retention_days',
                'public_project_reference',
                'background_image_mode',
                'background_image_rotation',
                'custom_background_image'
            ];
            fields.forEach(function (field) {
                setFieldError(field, errors[field] || null);
            });
            setActionMessage(errors.form || null);
        };
        const getLocalImageError = function () {
            if (!hasPendingCustomImage()) {
                return null;
            }
            const file = imageInput.files[0];
            if (file.size < 1 || file.size > config.maxCustomBackgroundImageUploadBytes) {
                return 'settings_error_image_upload_size';
            }
            if ((file.type && file.type !== 'image/png') || !/\.png$/i.test(file.name)) {
                return 'settings_error_image_invalid';
            }
            return null;
        };
        const validate = function () {
            const requestSequence = ++validationSequence;
            const localImageError = getLocalImageError();
            const payload = getCurrentValues();
            payload.has_pending_custom_image = hasPendingCustomImage();

            return module.ajax(config.validationAction, payload).then(function (response) {
                if (requestSequence !== validationSequence) {
                    return false;
                }
                const errors = response && response.errors && typeof response.errors === 'object'
                    ? response.errors
                    : { form: 'settings_error_validation_unavailable' };
                if (localImageError) {
                    errors.custom_background_image = localImageError;
                }
                showValidationErrors(errors);
                const isValid = Object.keys(errors).length === 0;
                logger.log('Validated project settings.', { isValid: isValid, invalidFields: Object.keys(errors) });
                return isValid;
            }).catch(function () {
                if (requestSequence === validationSequence) {
                    showValidationErrors({ form: 'settings_error_validation_unavailable' });
                    logger.warn('Project settings validation request failed.');
                }
                return false;
            });
        };
        const scheduleValidation = function () {
            if (validationTimer !== null) {
                window.clearTimeout(validationTimer);
            }
            validationTimer = window.setTimeout(function () {
                validationTimer = null;
                validate();
            }, validationDelayMilliseconds);
        };

        const previewContentBounds = function () {
            const styles = window.getComputedStyle(previewArea);
            const horizontalPadding = parseFloat(styles.paddingLeft) + parseFloat(styles.paddingRight);
            const verticalPadding = parseFloat(styles.paddingTop) + parseFloat(styles.paddingBottom);
            return {
                width: Math.max(1, previewArea.clientWidth - horizontalPadding),
                height: Math.max(1, previewArea.clientHeight - verticalPadding)
            };
        };
        const updatePreview = function () {
            rotationOutput.textContent = rotation.value + '°';
            if (previewImage.hidden || !previewImage.naturalWidth || !previewImage.naturalHeight) {
                return;
            }

            const bounds = previewContentBounds();
            const baseScale = Math.min(
                1,
                previewMaximumWidth / previewImage.naturalWidth,
                previewMaximumHeight / previewImage.naturalHeight,
                bounds.width / previewImage.naturalWidth,
                bounds.height / previewImage.naturalHeight
            );
            const baseWidth = previewImage.naturalWidth * baseScale;
            const baseHeight = previewImage.naturalHeight * baseScale;
            const radians = Math.abs(Number(rotation.value) || 0) * Math.PI / 180;
            const rotatedWidth = (baseWidth * Math.abs(Math.cos(radians))) + (baseHeight * Math.abs(Math.sin(radians)));
            const rotatedHeight = (baseWidth * Math.abs(Math.sin(radians))) + (baseHeight * Math.abs(Math.cos(radians)));
            const fittedScale = Math.min(1, bounds.width / rotatedWidth, bounds.height / rotatedHeight);

            previewImage.style.transform = 'rotate(' + rotation.value + 'deg) scale(' + fittedScale + ')';
        };
        const refreshPreviewFromFile = function () {
            const file = imageInput.files && imageInput.files[0];
            if (!file) {
                return;
            }
            const reader = new FileReader();
            reader.addEventListener('load', function () {
                previewImage.src = reader.result;
                previewImage.hidden = false;
                previewEmpty.hidden = true;
            });
            reader.readAsDataURL(file);
        };

        form.addEventListener('input', function () {
            updateDirtyState();
            scheduleValidation();
        });
        form.addEventListener('change', function () {
            updateDirtyState();
            scheduleValidation();
        });
        rotation.addEventListener('input', updatePreview);
        imageInput.addEventListener('change', refreshPreviewFromFile);
        previewImage.addEventListener('load', updatePreview);
        if (typeof window.ResizeObserver === 'function') {
            const observer = new window.ResizeObserver(updatePreview);
            observer.observe(previewArea);
        } else {
            window.addEventListener('resize', updatePreview);
        }

        form.addEventListener('submit', function (event) {
            event.preventDefault();
            if (validationTimer !== null) {
                window.clearTimeout(validationTimer);
                validationTimer = null;
            }
            validate().then(function (isValid) {
                if (!isValid) {
                    const invalidControl = form.querySelector('.is-invalid');
                    if (invalidControl && typeof invalidControl.focus === 'function') {
                        invalidControl.focus();
                    }
                    return;
                }
                allowNavigation = true;
                logger.log('Submitting validated project settings.');
                form.submit();
            });
        });
        discardButton.addEventListener('click', function () {
            allowNavigation = true;
            window.location.reload();
        });
        window.addEventListener('beforeunload', function (event) {
            if (!allowNavigation && hasUnsavedChanges()) {
                event.preventDefault();
                event.returnValue = '';
            }
        });

        updateDirtyState();
        updatePreview();
        logger.log('Initialized project settings page.');
    }

    window.WatermarkedSignaturesProjectSettings = {
        init: init
    };
})(window, document);
