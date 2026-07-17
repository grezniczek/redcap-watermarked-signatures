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
    $image = imagecreatetruecolor(460, 120);
    $white = imagecolorallocate($image, 255, 255, 255);
    $black = imagecolorallocate($image, 0, 0, 0);
    imagefilledrectangle($image, 0, 0, 460, 120, $white);
    imageline($image, 40, 70, 410, 45, $black);
    ob_start();
    imagepng($image);
    $png = ob_get_clean();
    imagedestroy($image);

    $renderer = new Renderer();
    $watermarked = $renderer->renderBase64(
        base64_encode($png),
        $anchor,
        $payload['context_ref'],
        ReferenceGenerator::captureReference(),
        '2026-07-16T14:32:05Z'
    );
    $info = getimagesizefromstring($watermarked);
    assertTrue($info[0] === 460 && $info[1] === 158 && $info[2] === IMAGETYPE_PNG, 'Rendered PNG dimensions failed.');
    assertTrue(hash('sha256', $watermarked) !== hash('sha256', $png), 'Renderer did not change the PNG.');

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
}

echo "Watermarked Signatures smoke tests passed.\n";
