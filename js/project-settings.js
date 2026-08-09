(function (document) {
    'use strict';

    const imageInput = document.getElementById('sigwm-custom-image');
    const previewImage = document.getElementById('sigwm-custom-image-preview');
    const previewEmpty = document.getElementById('sigwm-custom-image-preview-empty');
    const rotation = document.getElementById('sigwm-background-rotation');
    const rotationOutput = document.getElementById('sigwm-background-rotation-output');

    if (!imageInput || !previewImage || !previewEmpty || !rotation || !rotationOutput) {
        return;
    }

    const updateRotation = function () {
        previewImage.style.transform = 'rotate(' + rotation.value + 'deg)';
        rotationOutput.textContent = rotation.value + '°';
    };

    rotation.addEventListener('input', updateRotation);
    updateRotation();

    imageInput.addEventListener('change', function () {
        const file = imageInput.files && imageInput.files[0];
        if (!file) {
            return;
        }
        const reader = new FileReader();
        reader.addEventListener('load', function () {
            previewImage.src = reader.result;
            previewImage.hidden = false;
            previewEmpty.hidden = true;
            updateRotation();
        });
        reader.readAsDataURL(file);
    });
})(document);
