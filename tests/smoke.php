<?php

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
    imagedestroy($image);
    return $png;
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

$tampered = substr($envelope, 0, -1) . (substr($envelope, -1) === 'A' ? 'B' : 'A');
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
assertTrue((bool) preg_match('/^[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}$/', $anchor), 'Anchor format failed.');

if (extension_loaded('gd')) {
    $png = signaturePng(460, 120);

    $renderer = new Renderer();
    $captureReference = ReferenceGenerator::captureReference();
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
    imagedestroy($blackImage);

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
    imagedestroy($crossingImage);
    assertTrue($visibleCrossingPixels > 100, 'The overlay is not visibly distinguishable over black strokes.');

    $formatCases = array(
        array(80, 30, false, false),
        array(160, 60, true, true),
        array(460, 120, false, false),
        array(1024, 240, true, false)
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
            imagedestroy($caseImage);
        }
    }

    $longestFooter = max(
        strlen('WM1 A:' . $anchor . ' C:' . preg_replace('/^C-/', '', $payload['context_ref'])),
        strlen('S:' . preg_replace('/^S-/', '', $captureReference) . ' 2026-07-16T14:32:05.381Z')
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
    imagedestroy($tiledImage);

    assertThrows(function () use ($renderer, $png, $payload, $captureReference) {
        $renderer->renderBase64(
            base64_encode($png),
            'INVALID-ANCHOR',
            $payload['context_ref'],
            $captureReference,
            '2026-07-16T14:32:05Z'
        );
    }, 'Renderer accepted an invalid anchor format.');

    assertThrows(function () use ($renderer, $png, $anchor, $payload, $captureReference) {
        $renderer->renderBase64(
            base64_encode($png),
            $anchor,
            $payload['context_ref'],
            $captureReference,
            '2026-07-16 14:32:05'
        );
    }, 'Renderer accepted a non-UTC watermark timestamp.');
}

echo "Watermarked Signatures smoke tests passed.\n";
