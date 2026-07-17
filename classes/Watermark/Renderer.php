<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Watermark;

/**
 * Portable, deterministic GD renderer for the WM1 image format.
 */
class Renderer
{
    const VERSION = 1;
    const MAX_DECODED_BYTES = 6291456;
    const MAX_DIMENSION = 4096;
    const MAX_PIXELS = 12000000;
    const MIN_OUTPUT_WIDTH = 300;
    const FOOTER_HEIGHT = 38;
    const FONT = 2;

    public function renderBase64($encodedPng, $anchor, $contextReference, $captureReference, $capturedAt)
    {
        if (!extension_loaded('gd')) {
            throw new \RuntimeException('The GD PHP extension is required to watermark signatures.');
        }
        self::validateWatermarkValues($anchor, $contextReference, $captureReference, $capturedAt);
        if (!is_string($encodedPng) || $encodedPng === '') {
            throw new \InvalidArgumentException('The submitted signature image is empty.');
        }
        if (strlen($encodedPng) > (self::MAX_DECODED_BYTES * 2)) {
            throw new \InvalidArgumentException('The submitted signature image is too large.');
        }

        $bytes = base64_decode(str_replace(' ', '+', $encodedPng), true);
        if ($bytes === false || $bytes === '') {
            throw new \InvalidArgumentException('The submitted signature is not valid base64.');
        }
        if (strlen($bytes) > self::MAX_DECODED_BYTES) {
            throw new \InvalidArgumentException('The submitted signature image is too large.');
        }

        $imageInfo = @getimagesizefromstring($bytes);
        if ($imageInfo === false || $imageInfo[2] !== IMAGETYPE_PNG) {
            throw new \InvalidArgumentException('The submitted signature must be a valid PNG image.');
        }

        $width = (int) $imageInfo[0];
        $height = (int) $imageInfo[1];
        if ($width < 80 || $height < 30) {
            throw new \InvalidArgumentException('The submitted signature image is too small.');
        }
        if ($width > self::MAX_DIMENSION || $height > self::MAX_DIMENSION || ($width * $height) > self::MAX_PIXELS) {
            throw new \InvalidArgumentException('The submitted signature dimensions are not allowed.');
        }

        $source = @imagecreatefromstring($bytes);
        if ($source === false) {
            throw new \InvalidArgumentException('The submitted signature PNG could not be decoded.');
        }

        // Small signature widgets do not have enough horizontal space for the
        // complete identifiers. Widen the normalized output instead of
        // truncating security-relevant footer values.
        $outputWidth = max($width, self::MIN_OUTPUT_WIDTH);
        $outputHeight = $height + self::FOOTER_HEIGHT;
        $canvas = imagecreatetruecolor($outputWidth, $outputHeight);
        if ($canvas === false) {
            imagedestroy($source);
            throw new \RuntimeException('Could not allocate the watermark output image.');
        }

        $white = imagecolorallocate($canvas, 255, 255, 255);
        imagefilledrectangle($canvas, 0, 0, $outputWidth, $outputHeight, $white);
        imagealphablending($canvas, true);
        $signatureX = (int) floor(($outputWidth - $width) / 2);
        imagecopy($canvas, $source, $signatureX, 0, 0, 0, $width, $height);

        // Use a light edge under a blue center. A single dark translucent color
        // becomes nearly indistinguishable where it crosses black signature
        // strokes, which makes the signature appear to be painted on top even
        // though the watermark is rendered later. The offset light pass keeps
        // crossings visible on dark strokes; the blue pass remains visible on
        // the white signature background.
        $overlayEdgeColor = imagecolorallocatealpha($canvas, 255, 255, 255, 88);
        $overlayColor = imagecolorallocatealpha($canvas, 100, 160, 200, 75);
        $overlay = self::compact($anchor) . ' ' .
            substr(self::compact($contextReference), 0, 9) . ' ' .
            substr(self::compact($captureReference), 0, 9);
        $font = self::FONT;
        $textWidth = imagefontwidth($font) * strlen($overlay);
        $stepX = max(150, $textWidth + 55);

        for ($y = 8, $row = 0; $y < $height - 8; $y += 28, $row++) {
            $offset = ($row % 2) * (int) floor($stepX / 2);
            for ($x = -$offset; $x < $outputWidth; $x += $stepX) {
                imagestring($canvas, $font, $x + 1, $y + 1, $overlay, $overlayEdgeColor);
                imagestring($canvas, $font, $x, $y, $overlay, $overlayColor);
            }
        }

        $band = imagecolorallocate($canvas, 235, 241, 245);
        $line = imagecolorallocate($canvas, 75, 95, 110);
        $text = imagecolorallocate($canvas, 20, 35, 45);
        imagefilledrectangle($canvas, 0, $height, $outputWidth, $outputHeight, $band);
        imageline($canvas, 0, $height, $outputWidth, $height, $line);

        $line1 = 'WM' . self::VERSION . ' A:' . $anchor . ' C:' . self::withoutPrefix($contextReference);
        $line2 = 'S:' . self::withoutPrefix($captureReference) . ' ' . $capturedAt;
        imagestring($canvas, $font, 5, $height + 4, self::fitText($line1, $outputWidth, $font), $text);
        imagestring($canvas, $font, 5, $height + 20, self::fitText($line2, $outputWidth, $font), $text);

        ob_start();
        $encoded = imagepng($canvas, null, 6);
        $output = ob_get_clean();

        imagedestroy($canvas);
        imagedestroy($source);

        if (!$encoded || !is_string($output) || $output === '') {
            throw new \RuntimeException('Could not encode the watermarked signature PNG.');
        }

        return $output;
    }

    private static function validateWatermarkValues($anchor, $contextReference, $captureReference, $capturedAt)
    {
        $alphabet = '[0-9A-HJKMNP-TV-Z]';
        if (!is_string($anchor) || !preg_match('/^' . $alphabet . '{4}(?:-' . $alphabet . '{4}){3}$/D', $anchor)) {
            throw new \InvalidArgumentException('The watermark anchor format is invalid.');
        }
        if (!is_string($contextReference) || !preg_match('/^C-' . $alphabet . '{4}-' . $alphabet . '{4}-' . $alphabet . '{4}-' . $alphabet . '$/D', $contextReference)) {
            throw new \InvalidArgumentException('The watermark context reference format is invalid.');
        }
        if (!is_string($captureReference) || !preg_match('/^S-' . $alphabet . '{4}-' . $alphabet . '{4}-' . $alphabet . '{4}-' . $alphabet . '$/D', $captureReference)) {
            throw new \InvalidArgumentException('The watermark capture reference format is invalid.');
        }
        if (!is_string($capturedAt) || !preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/D', $capturedAt)) {
            throw new \InvalidArgumentException('The watermark timestamp must be UTC ISO 8601.');
        }
    }

    private static function compact($value)
    {
        return str_replace('-', '', $value);
    }

    private static function withoutPrefix($value)
    {
        return preg_replace('/^[A-Z]-/', '', $value);
    }

    private static function fitText($value, $width, $font)
    {
        $maxCharacters = max(1, (int) floor(($width - 10) / imagefontwidth($font)));
        if (strlen($value) <= $maxCharacters) {
            return $value;
        }
        if ($maxCharacters <= 3) {
            return substr($value, 0, $maxCharacters);
        }
        return substr($value, 0, $maxCharacters - 3) . '...';
    }
}
