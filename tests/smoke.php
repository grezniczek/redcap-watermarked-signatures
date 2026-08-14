<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Tests;

require_once __DIR__ . '/../classes/Crypto/Base32.php';
require_once __DIR__ . '/../classes/Crypto/Base64Url.php';
require_once __DIR__ . '/../classes/Crypto/CanonicalJson.php';
require_once __DIR__ . '/../classes/Crypto/EnvelopeSigner.php';
require_once __DIR__ . '/../classes/Crypto/ReferenceGenerator.php';
require_once __DIR__ . '/../classes/Crypto/Anchor.php';
require_once __DIR__ . '/../classes/Watermark/Renderer.php';

use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\Anchor;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\CanonicalJson;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\EnvelopeSigner;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
use DE\RUB\WatermarkedSignaturesExternalModule\Watermark\Renderer;
use RuntimeException;
use Throwable;

function assertTrue($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function assertThrows($callback, $message)
{
    $thrown = false;
    try {
        $callback();
    } catch (Throwable $exception) {
        $thrown = true;
    }
    assertTrue($thrown, $message);
}

function signaturePng($width, $height, $typed = false, $transparent = false)
{
    $image = imagecreatetruecolor($width, $height);
    if ($transparent) {
        imagealphablending($image, false);
        imagesavealpha($image, true);
        $background = imagecolorallocatealpha($image, 255, 255, 255, 127);
    } else {
        $background = imagecolorallocate($image, 255, 255, 255);
    }
    imagefilledrectangle($image, 0, 0, $width, $height, $background);
    imagealphablending($image, true);

    $ink = imagecolorallocate($image, 0, 0, 0);
    if ($typed === true) {
        imagestring($image, 5, 8, max(3, (int) floor(($height - imagefontheight(5)) / 2)), 'Ada Lovelace', $ink);
    } elseif ($typed === false) {
        imageline($image, max(5, (int) ($width * 0.08)), (int) ($height * 0.65), (int) ($width * 0.9), (int) ($height * 0.35), $ink);
    }

    ob_start();
    imagepng($image);
    $png = ob_get_clean();
    return $png;
}

function denseBlackAndWhitePng($width, $height)
{
    $image = imagecreatetruecolor($width, $height);
    $black = imagecolorallocate($image, 0, 0, 0);
    $white = imagecolorallocate($image, 255, 255, 255);
    $seed = 1234567;
    for ($y = 0; $y < $height; $y++) {
        for ($x = 0; $x < $width; $x++) {
            $seed = ($seed * 1103515245 + 12345) & 0x7fffffff;
            imagesetpixel($image, $x, $y, (($seed >> 16) & 1) === 1 ? $black : $white);
        }
    }

    ob_start();
    imagepng($image, null, 6);
    return ob_get_clean();
}

assertTrue(
    CanonicalJson::encode(array('z' => 1, 'a' => array('d' => 4, 'b' => 2))) === '{"a":{"b":2,"d":4},"z":1}',
    'Canonical JSON ordering failed.'
);

$signer = new EnvelopeSigner(str_repeat('k', 32));
$payload = array(
    'v' => 1,
    'pid' => 123,
    'event_id' => 417,
    'instrument' => 'consent',
    'field' => 'participant_signature',
    'context_ref' => ReferenceGenerator::contextReference(),
    'record_ref' => null,
    'project_reference' => null,
    'issued_at' => 1784212200,
    'expires_at' => 1784219400,
    'nonce' => ReferenceGenerator::nonce(),
    'purpose' => 'signature'
);
$envelope = $signer->sign($payload);
assertTrue(
    CanonicalJson::encode($signer->verify($envelope)) === CanonicalJson::encode($payload),
    'Envelope round trip failed.'
);

list($encodedPayload, $encodedMac) = explode('.', $envelope, 2);
$encodedPayload[0] = $encodedPayload[0] === 'A' ? 'B' : 'A';
$tampered = $encodedPayload . '.' . $encodedMac;
$tamperRejected = false;
try {
    $signer->verify($tampered);
} catch (Throwable $exception) {
    $tamperRejected = true;
}
assertTrue($tamperRejected, 'Envelope tampering was not rejected.');

$scope = array(
    'v' => 1,
    'pid' => 123,
    'event_id' => 417,
    'instrument' => 'consent',
    'field' => 'participant_signature'
);
$anchor = Anchor::create($scope, str_repeat('a', 32));
assertTrue((bool) preg_match('/^A:[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}$/', $anchor), 'Anchor format failed.');

if (extension_loaded('gd')) {
    $png = signaturePng(460, 120);

    $renderer = new Renderer();
    $captureReference = ReferenceGenerator::captureReference();
    $largestBlackAndWhitePng = denseBlackAndWhitePng(
        Renderer::MAX_SIGNATURE_IMAGE_WIDTH,
        Renderer::MAX_SIGNATURE_IMAGE_HEIGHT
    );
    assertTrue(
        strlen($largestBlackAndWhitePng) <= Renderer::MAX_SIGNATURE_IMAGE_BYTES,
        'A dense black-and-white signature does not fit the upload size limit.'
    );
    $watermarked = $renderer->renderBase64(
        base64_encode($png),
        $anchor,
        $payload['context_ref'],
        $captureReference,
        '2026-07-16T14:32:05Z'
    );
    $info = getimagesizefromstring($watermarked);
    assertTrue($info[0] === 460 && $info[1] === 158 && $info[2] === IMAGETYPE_PNG, 'Rendered PNG dimensions failed.');
    assertTrue(hash('sha256', $watermarked) !== hash('sha256', $png), 'Renderer did not change the PNG.');

    $customBackground = signaturePng(64, 24, true, true);
    $customBackgroundInfo = Renderer::validateCustomBackgroundImage($customBackground);
    assertTrue(
        $customBackgroundInfo === array('width' => 64, 'height' => 24),
        'Custom background image dimensions were not returned correctly.'
    );
    $customBackgroundWatermark = $renderer->renderBase64(
        base64_encode($png),
        $anchor,
        $payload['context_ref'],
        $captureReference,
        '2026-07-16T14:32:05Z',
        null,
        array('mode' => 'custom', 'contents' => $customBackground)
    );
    $noBackgroundWatermark = $renderer->renderBase64(
        base64_encode($png),
        $anchor,
        $payload['context_ref'],
        $captureReference,
        '2026-07-16T14:32:05Z',
        null,
        array('mode' => 'none')
    );
    assertTrue(
        !hash_equals($customBackgroundWatermark, $noBackgroundWatermark),
        'A custom background image did not affect the rendered PNG.'
    );
    assertThrows(function () {
        Renderer::validateCustomBackgroundImage(signaturePng(15, 16));
    }, 'Renderer accepted a custom background image below the minimum dimensions.');
    assertThrows(function () {
        Renderer::validateCustomBackgroundImage(signaturePng(513, 16));
    }, 'Renderer accepted a custom background image above the maximum dimensions.');
    assertThrows(function () {
        Renderer::validateCustomBackgroundImage('not a PNG');
    }, 'Renderer accepted an invalid custom background image.');
    $normalizedBackground = Renderer::normalizeCustomBackgroundImage(signaturePng(1024, 512, true, true));
    $normalizedBackgroundInfo = Renderer::validateCustomBackgroundImage($normalizedBackground);
    assertTrue(
        $normalizedBackgroundInfo === array('width' => 512, 'height' => 256),
        'Renderer did not normalize a large custom background image to the stored dimensions.'
    );
    $zeroRotationWatermark = $renderer->renderBase64(
        base64_encode($png),
        $anchor,
        $payload['context_ref'],
        $captureReference,
        '2026-07-16T14:32:05Z',
        null,
        array('mode' => 'custom', 'contents' => $customBackground, 'rotation' => 0)
    );
    $rightAngleRotationWatermark = $renderer->renderBase64(
        base64_encode($png),
        $anchor,
        $payload['context_ref'],
        $captureReference,
        '2026-07-16T14:32:05Z',
        null,
        array('mode' => 'custom', 'contents' => $customBackground, 'rotation' => 90)
    );
    assertTrue(
        !hash_equals($zeroRotationWatermark, $rightAngleRotationWatermark),
        'Custom background image rotation did not affect the rendered PNG.'
    );
    assertThrows(function () use ($renderer, $png, $anchor, $payload, $captureReference, $customBackground) {
        $renderer->renderBase64(
            base64_encode($png),
            $anchor,
            $payload['context_ref'],
            $captureReference,
            '2026-07-16T14:32:05Z',
            null,
            array('mode' => 'custom', 'contents' => $customBackground, 'rotation' => 181)
        );
    }, 'Renderer accepted an invalid custom background image rotation.');

    $publicReference = 'SIGWM-TEST-2026';
    $watermarkedWithReference = $renderer->renderBase64(
        base64_encode($png),
        $anchor,
        $payload['context_ref'],
        $captureReference,
        '2026-07-16T14:32:05Z',
        $publicReference
    );
    $referenceInfo = getimagesizefromstring($watermarkedWithReference);
    assertTrue(
        $referenceInfo[1] === 120 + Renderer::FOOTER_HEIGHT,
        'A public project reference changed the two-line footer height.'
    );
    assertTrue(!hash_equals($watermarked, $watermarkedWithReference), 'Public project reference did not affect the rendered footer.');

    $combinedReference = str_repeat('P', Renderer::MAX_PROJECT_REFERENCE_LENGTH)
        . ':' . str_repeat('F', Renderer::MAX_FIELD_REFERENCE_LENGTH);
    $watermarkedWithCombinedReference = $renderer->renderBase64(
        base64_encode($png),
        $anchor,
        $payload['context_ref'],
        $captureReference,
        '2026-07-16T14:32:05Z',
        $combinedReference
    );
    assertTrue(!hash_equals($watermarked, $watermarkedWithCombinedReference), 'A combined project and field reference did not affect the rendered footer.');

    $sameWatermark = $renderer->renderBase64(
        base64_encode($png),
        $anchor,
        $payload['context_ref'],
        $captureReference,
        '2026-07-16T14:32:05Z'
    );
    assertTrue(hash_equals($watermarked, $sameWatermark), 'Identical WM1 inputs did not render deterministically.');

    $otherCaptureWatermark = $renderer->renderBase64(
        base64_encode($png),
        $anchor,
        $payload['context_ref'],
        ReferenceGenerator::captureReference(),
        '2026-07-16T14:32:05Z'
    );
    assertTrue(!hash_equals(hash('sha256', $watermarked), hash('sha256', $otherCaptureWatermark)), 'Capture reference did not affect the final PNG digest.');

    // A watermark crossing a black stroke must remain visibly different from
    // black. This guards against an overlay that is technically painted last
    // but visually disappears into the signature.
    $blackImage = imagecreatetruecolor(460, 120);
    $solidBlack = imagecolorallocate($blackImage, 0, 0, 0);
    imagefilledrectangle($blackImage, 0, 0, 460, 120, $solidBlack);
    ob_start();
    imagepng($blackImage);
    $blackPng = ob_get_clean();

    $crossing = $renderer->renderBase64(
        base64_encode($blackPng),
        $anchor,
        $payload['context_ref'],
        ReferenceGenerator::captureReference(),
        '2026-07-16T14:32:05Z'
    );
    $crossingImage = imagecreatefromstring($crossing);
    $visibleCrossingPixels = 0;
    for ($y = 8; $y < 90; $y++) {
        for ($x = 0; $x < 460; $x++) {
            $rgb = imagecolorat($crossingImage, $x, $y);
            $red = ($rgb >> 16) & 0xff;
            $green = ($rgb >> 8) & 0xff;
            $blue = $rgb & 0xff;
            if (max($red, $green, $blue) >= 60) {
                $visibleCrossingPixels++;
            }
        }
    }
    assertTrue($visibleCrossingPixels > 100, 'The overlay is not visibly distinguishable over black strokes.');

    $formatCases = array(
        array(80, 30, false, false),
        array(160, 60, true, true),
        array(460, 120, false, false),
        array(Renderer::MAX_SIGNATURE_IMAGE_WIDTH, Renderer::MAX_SIGNATURE_IMAGE_HEIGHT, true, false)
    );
    foreach ($formatCases as $case) {
        list($sourceWidth, $sourceHeight, $typed, $transparent) = $case;
        $casePng = signaturePng($sourceWidth, $sourceHeight, $typed, $transparent);
        $caseOutput = $renderer->renderBase64(
            base64_encode($casePng),
            $anchor,
            $payload['context_ref'],
            $captureReference,
            '2026-07-16T14:32:05.381Z'
        );
        $caseInfo = getimagesizefromstring($caseOutput);
        assertTrue(
            $caseInfo[0] === max($sourceWidth, Renderer::MIN_OUTPUT_WIDTH)
                && $caseInfo[1] === $sourceHeight + Renderer::FOOTER_HEIGHT,
            "WM1 dimensions failed for {$sourceWidth}x{$sourceHeight}."
        );

        if ($transparent) {
            $caseImage = imagecreatefromstring($caseOutput);
            $sourceLeft = (int) floor(($caseInfo[0] - $sourceWidth) / 2);
            assertTrue((imagecolorat($caseImage, $sourceLeft + 1, 1) & 0xffffff) === 0xffffff, 'Transparent typed signature was not normalized onto white.');
        }
    }

    $longestFooter = max(
        strlen('WM1 S:' . preg_replace('/^S:/', '', $captureReference) . ' A:' . preg_replace('/^A:/', '', $anchor) . ' C:' . preg_replace('/^C:/', '', $payload['context_ref'])),
        strlen('TS:2026-07-16T14:32:05.381Z REF:' . str_repeat('X', Renderer::MAX_VISIBLE_REFERENCE_LENGTH))
    );
    assertTrue(
        Renderer::MIN_OUTPUT_WIDTH >= 10 + ($longestFooter * imagefontwidth(Renderer::FONT)),
        'Minimum WM1 width cannot preserve the complete footer identifiers.'
    );

    $blankPng = signaturePng(900, 180, null, false);
    $tiledOutput = $renderer->renderBase64(
        base64_encode($blankPng),
        $anchor,
        $payload['context_ref'],
        $captureReference,
        '2026-07-16T14:32:05Z'
    );
    $tiledImage = imagecreatefromstring($tiledOutput);
    for ($regionY = 0; $regionY < 3; $regionY++) {
        for ($regionX = 0; $regionX < 3; $regionX++) {
            $markedPixels = 0;
            for ($y = $regionY * 60; $y < ($regionY + 1) * 60; $y++) {
                for ($x = $regionX * 300; $x < ($regionX + 1) * 300; $x++) {
                    $rgb = imagecolorat($tiledImage, $x, $y);
                    $red = ($rgb >> 16) & 0xff;
                    $green = ($rgb >> 8) & 0xff;
                    $blue = $rgb & 0xff;
                    if ($red < 240 || $green < 240 || $blue < 240) {
                        $markedPixels++;
                    }
                }
            }
            assertTrue($markedPixels > 10, "Repeated overlay did not reach tile {$regionX},{$regionY}.");
        }
    }
    assertThrows(function () use ($renderer, $png, $payload, $captureReference) {
        $renderer->renderBase64(
            base64_encode($png),
            'INVALID-ANCHOR',
            $payload['context_ref'],
            $captureReference,
            '2026-07-16T14:32:05Z'
        );
    }, 'Renderer accepted an invalid anchor format.');

    assertThrows(function () use ($renderer, $png, $payload, $captureReference) {
        $renderer->renderBase64(
            base64_encode($png),
            'A-AAAA-BBBB-CCCC-DDDD',
            $payload['context_ref'],
            $captureReference,
            '2026-07-16T14:32:05Z'
        );
    }, 'Renderer accepted the retired A- anchor format.');

    assertThrows(function () use ($renderer, $anchor, $payload, $captureReference) {
        $renderer->renderBase64(
            base64_encode(signaturePng(Renderer::MAX_SIGNATURE_IMAGE_WIDTH + 1, Renderer::MAX_SIGNATURE_IMAGE_HEIGHT)),
            $anchor,
            $payload['context_ref'],
            $captureReference,
            '2026-07-16T14:32:05Z'
        );
    }, 'Renderer accepted a signature wider than the 2x canvas limit.');

    assertThrows(function () use ($renderer, $anchor, $payload, $captureReference) {
        $renderer->renderBase64(
            base64_encode(signaturePng(Renderer::MAX_SIGNATURE_IMAGE_WIDTH, Renderer::MAX_SIGNATURE_IMAGE_HEIGHT + 1)),
            $anchor,
            $payload['context_ref'],
            $captureReference,
            '2026-07-16T14:32:05Z'
        );
    }, 'Renderer accepted a signature taller than the 2x canvas limit.');

    assertThrows(function () use ($renderer, $anchor, $payload, $captureReference) {
        $renderer->renderBase64(
            str_repeat('A', Renderer::MAX_SIGNATURE_IMAGE_BASE64_BYTES + 1),
            $anchor,
            $payload['context_ref'],
            $captureReference,
            '2026-07-16T14:32:05Z'
        );
    }, 'Renderer accepted an encoded signature larger than 100 KiB.');

    assertThrows(function () use ($renderer, $png, $anchor, $payload, $captureReference) {
        $renderer->renderBase64(
            base64_encode($png),
            $anchor,
            $payload['context_ref'],
            $captureReference,
            '2026-07-16 14:32:05'
        );
    }, 'Renderer accepted a non-UTC watermark timestamp.');

    assertThrows(function () use ($renderer, $png, $anchor, $payload, $captureReference) {
        $renderer->renderBase64(
            base64_encode($png),
            $anchor,
            $payload['context_ref'],
            $captureReference,
            '2026-07-16T14:32:05Z',
            str_repeat('X', Renderer::MAX_VISIBLE_REFERENCE_LENGTH + 1)
        );
    }, 'Renderer accepted an oversized public project reference.');
}

echo "Watermarked Signatures smoke tests passed.\n";
