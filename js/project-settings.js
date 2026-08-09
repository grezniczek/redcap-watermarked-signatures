(function (window, document) {
    'use strict';

    const validationDelayMilliseconds = 350;
    // These dimensions match the minimum REDCap signature canvas and the WM1
    // footer produced by Renderer. The canvas preview is illustrative only:
    // it uses dummy provenance values instead of values from a real capture.
    const previewSignatureHeight = 120;
    const previewFooterHeight = 38;
    const previewWidth = 460;

    function init(module, config) {
        const form = document.getElementById('sigwm-project-settings-form');
        const imageInput = document.getElementById('sigwm-custom-image');
        const watermarkPreview = document.getElementById('sigwm-watermark-preview');
        const previewImage = document.getElementById('sigwm-custom-image-preview');
        const previewEmpty = document.getElementById('sigwm-custom-image-preview-empty');
        const rotation = document.getElementById('sigwm-background-rotation');
        const rotationOutput = document.getElementById('sigwm-background-rotation-output');
        const unsavedIndicator = document.getElementById('sigwm-settings-unsaved');
        const discardButton = document.getElementById('sigwm-settings-discard');
        const actionMessage = document.getElementById('sigwm-settings-action-message');

        if (!form || !imageInput || !watermarkPreview || !previewImage || !previewEmpty || !rotation || !rotationOutput || !unsavedIndicator || !discardButton || !actionMessage || !module) {
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
        const redcapLogo = document.createElement('img');
        const previewContext = watermarkPreview.getContext('2d');
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

        const hasLoadedImage = function (image) {
            return Boolean(image && image.complete && image.naturalWidth && image.naturalHeight);
        };
        const fitPreviewText = function (context, value, maximumWidth) {
            if (context.measureText(value).width <= maximumWidth) {
                return value;
            }
            let truncated = value;
            while (truncated.length > 3 && context.measureText(truncated + '...').width > maximumWidth) {
                truncated = truncated.slice(0, -1);
            }
            return truncated.length > 3 ? truncated + '...' : truncated;
        };
        const lightenedBackgroundImage = function (source) {
            const sourceMaximumDimension = Math.max(source.naturalWidth, source.naturalHeight);
            const scale = Math.min(1, 86 / sourceMaximumDimension);
            const width = Math.max(1, Math.round(source.naturalWidth * scale));
            const height = Math.max(1, Math.round(source.naturalHeight * scale));
            const imageCanvas = document.createElement('canvas');
            imageCanvas.width = width;
            imageCanvas.height = height;
            const imageContext = imageCanvas.getContext('2d');
            imageContext.drawImage(source, 0, 0, width, height);

            // Renderer lightens each non-transparent background pixel by 72%.
            imageContext.globalCompositeOperation = 'source-atop';
            imageContext.fillStyle = 'rgba(255, 255, 255, .72)';
            imageContext.fillRect(0, 0, width, height);
            imageContext.globalCompositeOperation = 'source-over';
            return imageCanvas;
        };
        const drawBackgroundPattern = function (context, source, rotationDegrees) {
            const background = lightenedBackgroundImage(source);
            const radians = -(Number(rotationDegrees) || 0) * Math.PI / 180;
            const cosine = Math.abs(Math.cos(radians));
            const sine = Math.abs(Math.sin(radians));
            const rotatedWidth = (background.width * cosine) + (background.height * sine);
            const rotatedHeight = (background.width * sine) + (background.height * cosine);
            const stepX = 132;
            const stepY = 47;

            for (let row = 0, y = -rotatedHeight; y < previewSignatureHeight; row += 1, y += stepY) {
                const offset = (row % 2) * Math.floor(stepX / 2);
                for (let x = -offset - rotatedWidth; x < previewWidth; x += stepX) {
                    context.save();
                    context.translate(x + (rotatedWidth / 2), y + (rotatedHeight / 2));
                    context.rotate(radians);
                    context.drawImage(background, -(background.width / 2), -(background.height / 2));
                    context.restore();
                }
            }
        };
        const drawDummySignature = function (context) {
            context.save();
            context.strokeStyle = '#101820';
            context.lineWidth = 2.1;
            context.lineCap = 'round';
            context.lineJoin = 'round';
            context.beginPath();
            context.moveTo(76, 82);
            context.bezierCurveTo(93, 28, 102, 89, 117, 69);
            context.bezierCurveTo(131, 50, 130, 47, 125, 79);
            context.bezierCurveTo(143, 58, 154, 57, 151, 81);
            context.bezierCurveTo(165, 63, 178, 58, 177, 81);
            context.bezierCurveTo(191, 64, 201, 58, 210, 76);
            context.bezierCurveTo(221, 91, 233, 76, 241, 66);
            context.bezierCurveTo(252, 52, 265, 54, 267, 76);
            context.bezierCurveTo(280, 63, 297, 61, 310, 75);
            context.bezierCurveTo(325, 90, 338, 78, 350, 69);
            context.stroke();
            context.beginPath();
            context.moveTo(95, 91);
            context.bezierCurveTo(158, 83, 238, 95, 337, 87);
            context.stroke();
            context.restore();
        };
        const drawIdentifierOverlay = function (context) {
            const overlay = 'S:56229F1FAHCAK A:ABCD1234EFGH5678 C:7JKM9NPQRSTV2';
            context.save();
            context.font = '10px monospace';
            context.textBaseline = 'top';
            const stepX = Math.max(150, context.measureText(overlay).width + 55);
            for (let row = 0, y = 8; y < previewSignatureHeight - 8; row += 1, y += 28) {
                const offset = (row % 2) * Math.floor(stepX / 2);
                for (let x = -offset; x < previewWidth; x += stepX) {
                    context.fillStyle = 'rgba(255, 255, 255, .31)';
                    context.fillText(overlay, x + 1, y + 1);
                    context.fillStyle = 'rgba(100, 160, 200, .41)';
                    context.fillText(overlay, x, y);
                }
            }
            context.restore();
        };
        const drawFooter = function (context) {
            context.save();
            context.fillStyle = '#ebf1f5';
            context.fillRect(0, previewSignatureHeight, previewWidth, previewFooterHeight);
            context.strokeStyle = '#4b5f6e';
            context.beginPath();
            context.moveTo(0, previewSignatureHeight + .5);
            context.lineTo(previewWidth, previewSignatureHeight + .5);
            context.stroke();
            context.fillStyle = '#14232d';
            context.font = '10px monospace';
            context.textBaseline = 'top';
            context.fillText(
                fitPreviewText(context, 'WM1 S:5622-9F1F-AHCA-K A:ABCD-1234-EFGH-5678 C:7JK-M9NP-QRST-V2', previewWidth - 10),
                5,
                previewSignatureHeight + 4
            );
            context.fillText('TS:2026-08-09T12:34:56Z REF:DEMO-42', 5, previewSignatureHeight + 20);
            context.restore();
        };
        const updatePreview = function () {
            rotationOutput.textContent = rotation.value + '°';
            if (!previewContext) {
                return;
            }
            const selectedMode = getSelectedBackgroundMode();
            const customImageAvailable = hasLoadedImage(previewImage);
            previewEmpty.hidden = selectedMode !== 'custom' || customImageAvailable;

            previewContext.clearRect(0, 0, watermarkPreview.width, watermarkPreview.height);
            previewContext.fillStyle = '#ffffff';
            previewContext.fillRect(0, 0, previewWidth, previewSignatureHeight);
            if (selectedMode === 'redcap' && hasLoadedImage(redcapLogo)) {
                drawBackgroundPattern(previewContext, redcapLogo, 20);
            } else if (selectedMode === 'custom' && customImageAvailable) {
                drawBackgroundPattern(previewContext, previewImage, rotation.value);
            }
            drawDummySignature(previewContext);
            drawIdentifierOverlay(previewContext);
            drawFooter(previewContext);
        };
        const refreshPreviewFromFile = function () {
            const file = imageInput.files && imageInput.files[0];
            if (!file) {
                return;
            }
            const reader = new FileReader();
            reader.addEventListener('load', function () {
                previewImage.src = reader.result;
            });
            reader.readAsDataURL(file);
        };

        form.addEventListener('input', function () {
            updateDirtyState();
            scheduleValidation();
        });
        form.addEventListener('change', function () {
            updateDirtyState();
            updatePreview();
            scheduleValidation();
        });
        rotation.addEventListener('input', updatePreview);
        imageInput.addEventListener('change', refreshPreviewFromFile);
        previewImage.addEventListener('load', updatePreview);
        redcapLogo.addEventListener('load', updatePreview);
        if (config.redcapLogoUrl) {
            redcapLogo.src = config.redcapLogoUrl;
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
