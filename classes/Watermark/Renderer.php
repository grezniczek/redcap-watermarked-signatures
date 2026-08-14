<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Watermark;

/**
 * Portable, deterministic GD renderer for the WM1 image format.
 */
class Renderer
{
	const VERSION = 1;
	// REDCap's drawing canvas is 460x120 pixels. Accept up to 2x in each
	// direction to tolerate browser/device pixel-density variation, without
	// allocating GD images from arbitrary public-survey uploads.
	const MAX_SIGNATURE_IMAGE_BYTES = 102400;
	const MAX_SIGNATURE_IMAGE_BASE64_BYTES = 136536;
	const MAX_SIGNATURE_IMAGE_WIDTH = 920;
	const MAX_SIGNATURE_IMAGE_HEIGHT = 240;
	const MAX_CUSTOM_BACKGROUND_IMAGE_SOURCE_DIMENSION = 4096;
	const MAX_CUSTOM_BACKGROUND_IMAGE_SOURCE_PIXELS = 12000000;
	const MIN_CUSTOM_BACKGROUND_IMAGE_DIMENSION = 16;
	const MAX_CUSTOM_BACKGROUND_IMAGE_DIMENSION = 512;
	const MAX_CUSTOM_BACKGROUND_IMAGE_BYTES = 1048576;
	const MAX_CUSTOM_BACKGROUND_IMAGE_UPLOAD_BYTES = 6291456;
	const MAX_BACKGROUND_IMAGE_DISPLAY_DIMENSION = 86;
	const DEFAULT_BACKGROUND_IMAGE_ROTATION = 20;
	const MIN_BACKGROUND_IMAGE_ROTATION = -180;
	const MAX_BACKGROUND_IMAGE_ROTATION = 180;
	const MIN_OUTPUT_WIDTH = 460;
	const FOOTER_HEIGHT = 38;
	const MAX_PROJECT_REFERENCE_LENGTH = 20;
	const MAX_FIELD_REFERENCE_LENGTH = 16;
	const MAX_LEGACY_PROJECT_REFERENCE_LENGTH = 30;
	const MAX_VISIBLE_REFERENCE_LENGTH = 37;
	const FONT = 2;

	/**
	 * @param string $encodedPng Base64-encoded PNG from REDCap's signature widget.
	 * @param string $anchor Visible A:-prefixed anchor.
	 * @param string $contextReference Visible C:-prefixed context reference.
	 * @param string $captureReference Visible S:-prefixed capture reference.
	 * @param string $capturedAt UTC ISO 8601 capture timestamp.
	 * @param string|null $projectReference Optional public reference shown after REF:.
	 * @param array{mode: 'redcap'|'custom'|'none', contents?: string|null, rotation?: int|string}|null $backgroundImage
	 * @return string Watermarked PNG bytes.
	 */
	public function renderBase64($encodedPng, $anchor, $contextReference, $captureReference, $capturedAt, $projectReference = null, $backgroundImage = null)
	{
		if (!extension_loaded('gd')) {
			throw new \RuntimeException('The GD PHP extension is required to watermark signatures.');
		}
		self::validateWatermarkValues($anchor, $contextReference, $captureReference, $capturedAt, $projectReference);
		$backgroundImage = self::normalizeBackgroundImage($backgroundImage);
		if (!is_string($encodedPng) || $encodedPng === '') {
			throw new \InvalidArgumentException('The submitted signature image is empty.');
		}
		if (strlen($encodedPng) > self::MAX_SIGNATURE_IMAGE_BASE64_BYTES) {
			throw new \InvalidArgumentException('The submitted signature image is too large.');
		}

		$bytes = base64_decode(str_replace(' ', '+', $encodedPng), true);
		if ($bytes === false || $bytes === '') {
			throw new \InvalidArgumentException('The submitted signature is not valid base64.');
		}
		if (strlen($bytes) > self::MAX_SIGNATURE_IMAGE_BYTES) {
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
		if ($width > self::MAX_SIGNATURE_IMAGE_WIDTH || $height > self::MAX_SIGNATURE_IMAGE_HEIGHT) {
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
			throw new \RuntimeException('Could not allocate the watermark output image.');
		}

		$white = imagecolorallocate($canvas, 255, 255, 255);
		imagefilledrectangle($canvas, 0, 0, $outputWidth, $outputHeight, $white);
		imagealphablending($canvas, true);
		$signatureX = (int) floor(($outputWidth - $width) / 2);

		self::drawBackgroundImagePattern($canvas, $outputWidth, $height, $backgroundImage);

		// Signature widgets submit either a transparent drawing or black ink
		// on an opaque white PNG. Treat only the white backing as transparent
		// so the logo remains the bottom layer and the signature ink is drawn
		// above it in both cases.
		imagecolortransparent($source, imagecolorallocate($source, 255, 255, 255));
		imagecopy($canvas, $source, $signatureX, 0, 0, 0, $width, $height);

		// Use a light edge under a blue center. A single dark translucent color
		// becomes nearly indistinguishable where it crosses black signature
		// strokes, which makes the signature appear to be painted on top even
		// though the watermark is rendered later. The offset light pass keeps
		// crossings visible on dark strokes; the blue pass remains visible on
		// the white signature background.
		$overlayEdgeColor = imagecolorallocatealpha($canvas, 255, 255, 255, 88);
		$overlayColor = imagecolorallocatealpha($canvas, 100, 160, 200, 75);
		// Use the complete, dashless values with their visible labels. This
		// preserves the familiar S:/A:/C: notation while keeping the repeated
		// overlay compact enough for REDCap's normalized 460px signature box.
		$overlay = 'S:' . self::compact(self::withoutPrefix($captureReference)) . ' ' .
			'A:' . self::compact(self::withoutPrefix($anchor)) . ' ' .
			'C:' . self::compact(self::withoutPrefix($contextReference));
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

		// Keep the user-entered capture reference at the start of the footer:
		// it is the identifier most often read directly from the image.
		$line1 = 'WM' . self::VERSION . ' S:' . self::withoutPrefix($captureReference) . ' A:' . self::withoutPrefix($anchor) . ' C:' . self::withoutPrefix($contextReference);
		$line2 = 'TS:' . $capturedAt . ($projectReference === null ? '' : ' REF:' . $projectReference);
		imagestring($canvas, $font, 5, $height + 4, self::fitText($line1, $outputWidth, $font), $text);
		imagestring($canvas, $font, 5, $height + 20, self::fitText($line2, $outputWidth, $font), $text);

		ob_start();
		$encoded = imagepng($canvas, null, 6);
		$output = ob_get_clean();

		if (!$encoded || !is_string($output) || $output === '') {
			throw new \RuntimeException('Could not encode the watermarked signature PNG.');
		}

		return $output;
	}

	/**
	 * Validate the retained project setting before its contents reach GD.
	 * The rendered signature canvas is small, so accepting larger source
	 * images would only consume memory before the image is scaled down.
	 *
	 * @param string $contents PNG bytes.
	 * @return array{width: int, height: int} Validated dimensions.
	 */
	public static function validateCustomBackgroundImage($contents)
	{
		if (!is_string($contents) || $contents === '') {
			throw new \InvalidArgumentException('The custom background image is empty.');
		}
		if (strlen($contents) > self::MAX_CUSTOM_BACKGROUND_IMAGE_BYTES) {
			throw new \InvalidArgumentException('The custom background image is too large.');
		}

		$imageInfo = @getimagesizefromstring($contents);
		if ($imageInfo === false || $imageInfo[2] !== IMAGETYPE_PNG) {
			throw new \InvalidArgumentException('The custom background image must be a valid PNG image.');
		}

		$width = (int) $imageInfo[0];
		$height = (int) $imageInfo[1];
		if (
			$width < self::MIN_CUSTOM_BACKGROUND_IMAGE_DIMENSION
			|| $height < self::MIN_CUSTOM_BACKGROUND_IMAGE_DIMENSION
			|| $width > self::MAX_CUSTOM_BACKGROUND_IMAGE_DIMENSION
			|| $height > self::MAX_CUSTOM_BACKGROUND_IMAGE_DIMENSION
		) {
			throw new \InvalidArgumentException('The custom background image dimensions are not allowed.');
		}

		$image = @imagecreatefromstring($contents);
		if ($image === false) {
			throw new \InvalidArgumentException('The custom background image PNG could not be decoded.');
		}
		return array('width' => $width, 'height' => $height);
	}

	/**
	 * Convert a project administrator's PNG upload into the bounded source
	 * asset used for every signature. This keeps costly resampling out of the
	 * capture path while preserving transparency.
	 *
	 * @param string $contents Uploaded PNG bytes.
	 * @return string Normalized PNG bytes.
	 */
	public static function normalizeCustomBackgroundImage($contents)
	{
		if (!extension_loaded('gd')) {
			throw new \RuntimeException('The GD PHP extension is required to normalize custom background images.');
		}
		if (!is_string($contents) || $contents === '') {
			throw new \InvalidArgumentException('The custom background image is empty.');
		}
		if (strlen($contents) > self::MAX_CUSTOM_BACKGROUND_IMAGE_UPLOAD_BYTES) {
			throw new \InvalidArgumentException('The uploaded custom background image is too large.');
		}

		$imageInfo = @getimagesizefromstring($contents);
		if ($imageInfo === false || $imageInfo[2] !== IMAGETYPE_PNG) {
			throw new \InvalidArgumentException('The custom background image must be a valid PNG image.');
		}

		$sourceWidth = (int) $imageInfo[0];
		$sourceHeight = (int) $imageInfo[1];
		if (
			$sourceWidth < self::MIN_CUSTOM_BACKGROUND_IMAGE_DIMENSION
			|| $sourceHeight < self::MIN_CUSTOM_BACKGROUND_IMAGE_DIMENSION
			|| $sourceWidth > self::MAX_CUSTOM_BACKGROUND_IMAGE_SOURCE_DIMENSION
			|| $sourceHeight > self::MAX_CUSTOM_BACKGROUND_IMAGE_SOURCE_DIMENSION
			|| ($sourceWidth * $sourceHeight) > self::MAX_CUSTOM_BACKGROUND_IMAGE_SOURCE_PIXELS
		) {
			throw new \InvalidArgumentException('The uploaded custom background image dimensions are not allowed.');
		}

		$source = @imagecreatefromstring($contents);
		if ($source === false) {
			throw new \InvalidArgumentException('The uploaded custom background image PNG could not be decoded.');
		}

		$scale = min(1, self::MAX_CUSTOM_BACKGROUND_IMAGE_DIMENSION / max($sourceWidth, $sourceHeight));
		$targetWidth = (int) round($sourceWidth * $scale);
		$targetHeight = (int) round($sourceHeight * $scale);
		if (
			$targetWidth < self::MIN_CUSTOM_BACKGROUND_IMAGE_DIMENSION
			|| $targetHeight < self::MIN_CUSTOM_BACKGROUND_IMAGE_DIMENSION
		) {
			throw new \InvalidArgumentException('The uploaded custom background image aspect ratio is not allowed.');
		}

		while (true) {
			$normalized = self::resamplePngImage($source, $sourceWidth, $sourceHeight, $targetWidth, $targetHeight);
			$output = self::encodePngImage($normalized);

			if (strlen($output) <= self::MAX_CUSTOM_BACKGROUND_IMAGE_BYTES) {
				self::validateCustomBackgroundImage($output);
				return $output;
			}

			$scale = sqrt((self::MAX_CUSTOM_BACKGROUND_IMAGE_BYTES / strlen($output)) * 0.95);
			$nextWidth = (int) floor($targetWidth * $scale);
			$nextHeight = (int) floor($targetHeight * $scale);
			if (
				$nextWidth < self::MIN_CUSTOM_BACKGROUND_IMAGE_DIMENSION
				|| $nextHeight < self::MIN_CUSTOM_BACKGROUND_IMAGE_DIMENSION
			) {
				throw new \InvalidArgumentException('The custom background image could not be normalized within the file-size limit.');
			}
			if ($nextWidth >= $targetWidth && $targetWidth > self::MIN_CUSTOM_BACKGROUND_IMAGE_DIMENSION) {
				$nextWidth = $targetWidth - 1;
			}
			if ($nextHeight >= $targetHeight && $targetHeight > self::MIN_CUSTOM_BACKGROUND_IMAGE_DIMENSION) {
				$nextHeight = $targetHeight - 1;
			}
			if ($nextWidth === $targetWidth && $nextHeight === $targetHeight) {
				throw new \InvalidArgumentException('The custom background image could not be normalized within the file-size limit.');
			}
			$targetWidth = $nextWidth;
			$targetHeight = $nextHeight;
		}
	}

	/**
	 * @param string $anchor
	 * @param string $contextReference
	 * @param string $captureReference
	 * @param string $capturedAt
	 * @param string|null $projectReference
	 * @return void
	 */
	private static function validateWatermarkValues($anchor, $contextReference, $captureReference, $capturedAt, $projectReference)
	{
		$alphabet = '[0-9A-HJKMNP-TV-Z]';
		if (!is_string($anchor) || !preg_match('/^A:' . $alphabet . '{4}(?:-' . $alphabet . '{4}){3}$/D', $anchor)) {
			throw new \InvalidArgumentException('The watermark anchor format is invalid.');
		}
		if (!is_string($contextReference) || !preg_match('/^C:' . $alphabet . '{4}-' . $alphabet . '{4}-' . $alphabet . '{4}-' . $alphabet . '$/D', $contextReference)) {
			throw new \InvalidArgumentException('The watermark context reference format is invalid.');
		}
		if (!is_string($captureReference) || !preg_match('/^S:' . $alphabet . '{4}-' . $alphabet . '{4}-' . $alphabet . '{4}-' . $alphabet . '$/D', $captureReference)) {
			throw new \InvalidArgumentException('The watermark capture reference format is invalid.');
		}
		if (!is_string($capturedAt) || !preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/D', $capturedAt)) {
			throw new \InvalidArgumentException('The watermark timestamp must be UTC ISO 8601.');
		}
		if (
			$projectReference !== null
			&& (!is_string($projectReference)
				|| strlen($projectReference) > self::MAX_VISIBLE_REFERENCE_LENGTH
				|| !preg_match('/^[A-Za-z0-9][A-Za-z0-9 ._\/-]*(?::[A-Za-z0-9][A-Za-z0-9 ._\/-]*)?$/D', $projectReference))
		) {
			throw new \InvalidArgumentException('The watermark public project reference is invalid.');
		}
	}

	/**
	 * @param array{mode: 'redcap'|'custom'|'none', contents?: string|null, rotation?: int|string}|null $backgroundImage
	 * @return array{mode: 'redcap'|'custom'|'none', contents: string|null, rotation: int}
	 */
	private static function normalizeBackgroundImage($backgroundImage)
	{
		if ($backgroundImage === null) {
			return array('mode' => 'redcap', 'contents' => null, 'rotation' => self::DEFAULT_BACKGROUND_IMAGE_ROTATION);
		}
		if (!is_array($backgroundImage) || !isset($backgroundImage['mode'])) {
			throw new \InvalidArgumentException('The watermark background image profile is invalid.');
		}

		$mode = $backgroundImage['mode'];
		if (!in_array($mode, array('redcap', 'custom', 'none'), true)) {
			throw new \InvalidArgumentException('The watermark background image mode is invalid.');
		}
		if ($mode === 'redcap') {
			return array('mode' => 'redcap', 'contents' => null, 'rotation' => self::DEFAULT_BACKGROUND_IMAGE_ROTATION);
		}
		if ($mode === 'none') {
			return array('mode' => 'none', 'contents' => null, 'rotation' => 0);
		}

		$contents = $backgroundImage['contents'] ?? null;
		self::validateCustomBackgroundImage($contents);
		return array(
			'mode' => 'custom',
			'contents' => $contents,
			'rotation' => self::normalizeBackgroundImageRotation($backgroundImage['rotation'] ?? self::DEFAULT_BACKGROUND_IMAGE_ROTATION)
		);
	}

	/**
	 * @param int|string $rotation
	 * @return int Rotation in degrees.
	 */
	private static function normalizeBackgroundImageRotation($rotation)
	{
		if (is_int($rotation)) {
			$normalized = $rotation;
		} elseif (is_string($rotation) && preg_match('/^-?(?:0|[1-9][0-9]{0,2})$/D', $rotation)) {
			$normalized = (int) $rotation;
		} else {
			throw new \InvalidArgumentException('The custom background image rotation is invalid.');
		}
		if ($normalized < self::MIN_BACKGROUND_IMAGE_ROTATION || $normalized > self::MAX_BACKGROUND_IMAGE_ROTATION) {
			throw new \InvalidArgumentException('The custom background image rotation is not allowed.');
		}
		return $normalized;
	}

	/**
	 * @param resource|\GdImage $source
	 * @param int $sourceWidth
	 * @param int $sourceHeight
	 * @param int $targetWidth
	 * @param int $targetHeight
	 * @return resource|\GdImage
	 */
	private static function resamplePngImage($source, $sourceWidth, $sourceHeight, $targetWidth, $targetHeight)
	{
		$target = imagecreatetruecolor($targetWidth, $targetHeight);
		if ($target === false) {
			throw new \RuntimeException('Could not allocate the normalized custom background image.');
		}
		imagealphablending($target, false);
		imagesavealpha($target, true);
		$transparent = imagecolorallocatealpha($target, 255, 255, 255, 127);
		imagefilledrectangle($target, 0, 0, $targetWidth - 1, $targetHeight - 1, $transparent);
		if (!imagecopyresampled($target, $source, 0, 0, 0, 0, $targetWidth, $targetHeight, $sourceWidth, $sourceHeight)) {
			throw new \RuntimeException('Could not normalize the custom background image.');
		}
		return $target;
	}

	/**
	 * @param resource|\GdImage $image
	 * @return string PNG bytes.
	 */
	private static function encodePngImage($image)
	{
		ob_start();
		$encoded = imagepng($image, null, 9);
		$output = ob_get_clean();
		if (!$encoded || !is_string($output) || $output === '') {
			throw new \RuntimeException('Could not encode the normalized custom background image.');
		}
		return $output;
	}

	/**
	 * @param string $value
	 * @return string Value with visible reference-group separators removed.
	 */
	private static function compact($value)
	{
		return str_replace('-', '', $value);
	}

	/**
	 * @param string $value Visible reference.
	 * @return string Value without its one-letter visible prefix.
	 */
	private static function withoutPrefix($value)
	{
		return preg_replace('/^[A-Z]:/', '', $value);
	}

	/**
	 * @param resource|\GdImage $canvas
	 * @param int $width
	 * @param int $height
	 * @param array{mode: 'redcap'|'custom'|'none', contents: string|null, rotation: int} $backgroundImage
	 * @return void
	 */
	private static function drawBackgroundImagePattern($canvas, $width, $height, $backgroundImage)
	{
		if ($backgroundImage['mode'] === 'none' || !function_exists('imagerotate')) {
			return;
		}

		if ($backgroundImage['mode'] === 'redcap') {
			if (!defined('APP_PATH_DOCROOT')) {
				return;
			}
			$path = rtrim((string) APP_PATH_DOCROOT, '/\\') . '/Resources/images/redcap-logo.png';
			$source = is_file($path) ? @imagecreatefrompng($path) : false;
		} else {
			$source = @imagecreatefromstring($backgroundImage['contents']);
		}
		if ($source === false) {
			if ($backgroundImage['mode'] === 'redcap') {
				return;
			}
			throw new \RuntimeException('The watermark background image could not be decoded.');
		}

		$sourceWidth = imagesx($source);
		$sourceHeight = imagesy($source);
		$scale = min(1, self::MAX_BACKGROUND_IMAGE_DISPLAY_DIMENSION / max($sourceWidth, $sourceHeight));
		$logoWidth = max(1, (int) round($sourceWidth * $scale));
		$logoHeight = max(1, (int) round($sourceHeight * $scale));
		$logo = imagecreatetruecolor($logoWidth, $logoHeight);
		if ($logo === false) {
			return;
		}
		imagealphablending($logo, false);
		imagesavealpha($logo, true);
		$transparent = imagecolorallocatealpha($logo, 255, 255, 255, 127);
		imagefilledrectangle($logo, 0, 0, $logoWidth - 1, $logoHeight - 1, $transparent);
		imagecopyresampled($logo, $source, 0, 0, 0, 0, $logoWidth, $logoHeight, $sourceWidth, $sourceHeight);
		for ($y = 0; $y < $logoHeight; $y++) {
			for ($x = 0; $x < $logoWidth; $x++) {
				$pixel = imagecolorat($logo, $x, $y);
				$red = ($pixel >> 16) & 0xff;
				$green = ($pixel >> 8) & 0xff;
				$blue = $pixel & 0xff;
				$color = imagecolorallocatealpha(
					$logo,
					(int) round($red + ((255 - $red) * 0.72)),
					(int) round($green + ((255 - $green) * 0.72)),
					(int) round($blue + ((255 - $blue) * 0.72)),
					($pixel >> 24) & 0x7f
				);
				imagesetpixel($logo, $x, $y, $color);
			}
		}

		$rotated = imagerotate($logo, $backgroundImage['rotation'], $transparent);
		if ($rotated === false) {
			return;
		}
		imagealphablending($rotated, true);
		imagesavealpha($rotated, true);

		$rotatedWidth = imagesx($rotated);
		$rotatedHeight = imagesy($rotated);
		$stepX = 132;
		$stepY = 47;
		for ($row = 0, $y = -$rotatedHeight; $y < $height; $row++, $y += $stepY) {
			$offset = ($row % 2) * (int) floor($stepX / 2);
			for ($x = -$offset - $rotatedWidth; $x < $width; $x += $stepX) {
				imagecopy($canvas, $rotated, $x, $y, 0, 0, $rotatedWidth, $rotatedHeight);
			}
		}
	}

	/**
	 * @param string $value
	 * @param int $width
	 * @param int $font GD built-in font identifier.
	 * @return string Text truncated to the available footer width.
	 */
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
