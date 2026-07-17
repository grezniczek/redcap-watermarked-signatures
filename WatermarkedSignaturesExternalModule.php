<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule;

use Exception;
use Throwable;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\Anchor;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\CanonicalJson;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\EnvelopeSigner;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\KeyDerivation;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
use DE\RUB\WatermarkedSignaturesExternalModule\Watermark\Renderer;

require_once "classes/ActionTagHelper.php";
require_once "classes/InjectionHelper.php";
require_once "classes/Crypto/Base32.php";
require_once "classes/Crypto/Base64Url.php";
require_once "classes/Crypto/CanonicalJson.php";
require_once "classes/Crypto/KeyDerivation.php";
require_once "classes/Crypto/EnvelopeSigner.php";
require_once "classes/Crypto/ReferenceGenerator.php";
require_once "classes/Crypto/Anchor.php";
require_once "classes/Watermark/Renderer.php";

class WatermarkedSignaturesExternalModule extends \ExternalModules\AbstractExternalModule
{
    private $js_debug = false;

    /** @var \Project */
    private $proj = null;
    private $project_id = null;

    const ACTIONTAG = "@WATERMARKED-SIGNATURE";
    const ENVELOPE_VERSION = 1;
    const ENVELOPE_TTL_SECONDS = 14400;
    const ENVELOPE_MAX_TTL_SECONDS = 28800;
    const CLOCK_SKEW_SECONDS = 300;

    #region Hooks

    function redcap_data_entry_form($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
    {
        $this->init_proj($project_id);
        $this->init_config();
        $this->inject_capture_envelopes($instrument, $event_id);
    }

    function redcap_survey_page($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        $this->init_proj($project_id);
        $this->init_config();
        $this->inject_capture_envelopes($instrument, $event_id);
    }

    /**
     * The signature receiver calls this hook before decoding myfile_base64.
     */
    function redcap_every_page_before_render($project_id)
    {
        if ($project_id == null || !$this->is_signature_upload_request()) {
            return;
        }

        $this->init_proj($project_id);
        $this->init_config();
        $this->intercept_signature_upload();
    }

    function redcap_every_page_top($project_id)
    {
        // Skip non-project context
        if ($project_id == null) return;

        // Initialize
        $this->init_proj($project_id);
        $this->init_config();
    }

    function redcap_module_ajax($action, $payload, $project_id, $record, $instrument, $event_id, $repeat_instance, $survey_hash, $response_id, $survey_queue_hash, $page, $page_full, $user_id, $group_id)
    {
        $this->init_proj($project_id);
        $user = $this->framework->getUser($user_id);
        $rights = $user->getRights($project_id);

        return null;
    }

    #endregion



    #region Private Helpers

    private function inject_capture_envelopes($instrument, $event_id)
    {
        $fields = $this->get_configured_signature_fields($instrument);
        if (empty($fields)) {
            return;
        }

        $now = time();
        $signer = new EnvelopeSigner(KeyDerivation::derive(KeyDerivation::ENVELOPE_INFO));
        $envelopes = array();

        foreach ($fields as $field) {
            $payload = array(
                "v" => self::ENVELOPE_VERSION,
                "pid" => (int) $this->project_id,
                "event_id" => (int) $event_id,
                "instrument" => (string) $instrument,
                "field" => (string) $field,
                "context_ref" => ReferenceGenerator::contextReference(),
                "record_ref" => null,
                "issued_at" => $now,
                "expires_at" => $now + self::ENVELOPE_TTL_SECONDS,
                "nonce" => ReferenceGenerator::nonce(),
                "purpose" => "signature"
            );
            $envelopes[$field] = $signer->sign($payload);
        }

        $config = json_encode(
            array(
                "envelopes" => $envelopes,
                "debug" => $this->js_debug
            ),
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
        );

        echo "<script type=\"text/javascript\">window.REDCapSignatureWatermark={$config};</script>";
        InjectionHelper::init($this)->js("js/signature-watermark.js");
    }

    private function intercept_signature_upload()
    {
        if (($_SERVER["REQUEST_METHOD"] ?? "") !== "POST") {
            return;
        }

        $field = $this->posted_field_name();
        if ($field === null) {
            return;
        }

        $metadata = $this->get_project_metadata();
        if (!isset($metadata[$field]) || !$this->is_configured_signature_field($metadata[$field])) {
            return;
        }

        $envelope = isset($_POST["sigwm_envelope"]) ? (string) $_POST["sigwm_envelope"] : "";
        if ($envelope === "") {
            $this->fail_upload($field, "sigwm_error_invalid_envelope", "The signed watermark envelope is missing.");
            return;
        }

        try {
            $signer = new EnvelopeSigner(KeyDerivation::derive(KeyDerivation::ENVELOPE_INFO));
            $payload = $signer->verify($envelope);
            $this->validate_envelope_payload($payload, $field, $metadata[$field]);
        } catch (Throwable $exception) {
            $this->fail_upload($field, "sigwm_error_invalid_envelope", $exception->getMessage());
            return;
        }

        $scope = array(
            "v" => Renderer::VERSION,
            "pid" => (int) $payload["pid"],
            "event_id" => (int) $payload["event_id"],
            "instrument" => (string) $payload["instrument"],
            "field" => (string) $payload["field"]
        );
        $anchor = Anchor::create($scope, KeyDerivation::derive(KeyDerivation::ANCHOR_INFO));
        $captureReference = ReferenceGenerator::captureReference();
        $capturedAt = gmdate("Y-m-d\TH:i:s\Z");

        try {
            $renderer = new Renderer();
            $watermarkedPng = $renderer->renderBase64(
                isset($_POST["myfile_base64"]) ? $_POST["myfile_base64"] : "",
                $anchor,
                $payload["context_ref"],
                $captureReference,
                $capturedAt
            );
        } catch (Throwable $exception) {
            $this->fail_upload($field, "sigwm_error_upload_render", $exception->getMessage());
            return;
        }

        $_POST["myfile_base64"] = base64_encode($watermarkedPng);
        $provenance = array(
            "v" => 1,
            "capture_ref" => $captureReference,
            "context_ref" => $payload["context_ref"],
            "record_ref" => isset($payload["record_ref"]) ? $payload["record_ref"] : null,
            "anchor" => $anchor,
            "pid" => (int) $payload["pid"],
            "event_id" => (int) $payload["event_id"],
            "instrument" => $payload["instrument"],
            "field" => $payload["field"],
            "captured_at" => $capturedAt,
            "file_sha256" => hash("sha256", $watermarkedPng),
            "envelope_nonce" => $payload["nonce"],
            "watermark_version" => Renderer::VERSION
        );

        $this->capture_edoc_id_from_response($field, $provenance);
    }

    private function validate_envelope_payload($payload, $postedField, $fieldMetadata)
    {
        $required = array(
            "v", "pid", "event_id", "instrument", "field", "context_ref",
            "record_ref", "issued_at", "expires_at", "nonce", "purpose"
        );
        foreach ($required as $key) {
            if (!array_key_exists($key, $payload)) {
                throw new \UnexpectedValueException("Envelope property '{$key}' is missing.");
            }
        }

        if ($payload["v"] !== self::ENVELOPE_VERSION || $payload["purpose"] !== "signature") {
            throw new \UnexpectedValueException("Unsupported signature watermark envelope.");
        }
        if (!is_int($payload["pid"]) || $payload["pid"] !== (int) $this->project_id) {
            throw new \UnexpectedValueException("Envelope project mismatch.");
        }
        if (!is_int($payload["event_id"]) || !$this->proj->validateEventId($payload["event_id"])) {
            throw new \UnexpectedValueException("Envelope event mismatch.");
        }
        $requestEventId = isset($_GET["event_id"]) && is_numeric($_GET["event_id"])
            ? (int) $_GET["event_id"]
            : null;
        if ($requestEventId === null || $payload["event_id"] !== $requestEventId) {
            throw new \UnexpectedValueException("Envelope event does not match the upload request.");
        }
        if (!is_string($payload["instrument"]) || $payload["instrument"] !== $fieldMetadata["form_name"]) {
            throw new \UnexpectedValueException("Envelope instrument mismatch.");
        }
        if (isset($_GET["page"]) && $_GET["page"] !== "" && $payload["instrument"] !== (string) $_GET["page"]) {
            throw new \UnexpectedValueException("Envelope instrument does not match the upload request.");
        }
        if (!$this->proj->validateFormEvent($payload["instrument"], $payload["event_id"])) {
            throw new \UnexpectedValueException("The envelope instrument is not assigned to the event.");
        }
        if (!is_string($payload["field"]) || $payload["field"] !== $postedField) {
            throw new \UnexpectedValueException("Envelope field mismatch.");
        }
        if (!is_string($payload["context_ref"]) || !preg_match('/^C-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]$/', $payload["context_ref"])) {
            throw new \UnexpectedValueException("Invalid envelope context reference.");
        }
        if ($payload["record_ref"] !== null
            && (!is_string($payload["record_ref"]) || !preg_match('/^R-[0-9A-HJKMNP-TV-Z-]+$/', $payload["record_ref"]))) {
            throw new \UnexpectedValueException("Invalid envelope record reference.");
        }
        if (!is_string($payload["nonce"]) || !preg_match('/^[A-Za-z0-9_-]{20,64}$/', $payload["nonce"])) {
            throw new \UnexpectedValueException("Invalid envelope nonce.");
        }
        if (!is_int($payload["issued_at"]) || !is_int($payload["expires_at"])) {
            throw new \UnexpectedValueException("Invalid envelope timestamps.");
        }

        $now = time();
        if ($payload["issued_at"] > $now + self::CLOCK_SKEW_SECONDS) {
            throw new \UnexpectedValueException("The signature watermark envelope is not valid yet.");
        }
        if ($payload["expires_at"] < $now) {
            throw new \UnexpectedValueException("The signature watermark envelope has expired.");
        }
        if ($payload["expires_at"] <= $payload["issued_at"]) {
            throw new \UnexpectedValueException("The signature watermark envelope lifetime is invalid.");
        }
        if (($payload["expires_at"] - $payload["issued_at"]) > self::ENVELOPE_MAX_TTL_SECONDS) {
            throw new \UnexpectedValueException("The signature watermark envelope lifetime is invalid.");
        }
    }

    private function capture_edoc_id_from_response($field, $provenance)
    {
        $module = $this;
        $recorded = false;
        $fieldPattern = preg_quote($field, '/');

        ob_start(function ($output) use ($module, &$recorded, $fieldPattern, $provenance) {
            if (!$recorded && preg_match(
                "/stopUpload\\(\\s*1\\s*,\\s*'{$fieldPattern}'\\s*,\\s*'([0-9]+)'/",
                $output,
                $matches
            )) {
                $recorded = true;
                $event = $provenance;
                $event["edoc_id"] = (int) $matches[1];
                $module->append_upload_provenance($event);
            }
            return $output;
        });
    }

    public function append_upload_provenance($event)
    {
        try {
            $this->log("sigwm_upload", array(
                "capture_ref" => $event["capture_ref"],
                "context_ref" => $event["context_ref"],
                "anchor" => $event["anchor"],
                "event_id" => $event["event_id"],
                "instrument" => $event["instrument"],
                "field" => $event["field"],
                "edoc_id" => $event["edoc_id"],
                "file_sha256" => $event["file_sha256"],
                "watermark_version" => $event["watermark_version"],
                "payload_json" => CanonicalJson::encode($event)
            ));
        } catch (Throwable $exception) {
            error_log("Watermarked Signatures provenance logging failed: " . $exception->getMessage());
        }
    }

    private function fail_upload($field, $eventType, $technicalMessage)
    {
        try {
            $this->log($eventType, array(
                "field" => $field,
                "event_id" => isset($_GET["event_id"]) && is_numeric($_GET["event_id"]) ? (int) $_GET["event_id"] : "",
                "technical_message" => substr((string) $technicalMessage, 0, 1000)
            ));
        } catch (Throwable $exception) {
            error_log("Watermarked Signatures error logging failed: " . $exception->getMessage());
        }

        $message = "The signature could not be securely watermarked. Please reopen the signature dialog and try again.";
        $fieldJson = json_encode($field);
        $messageJson = json_encode($message);
        $instance = isset($_GET["instance"]) && is_numeric($_GET["instance"]) && (int) $_GET["instance"] > 0
            ? (int) $_GET["instance"]
            : 1;
        echo "<script type=\"text/javascript\">
            window.parent.window.stopUpload(0, {$fieldJson}, '0', '', '', '', '', '', '', {$instance}, true);
            window.parent.window.alert({$messageJson});
        </script>";
        $this->exitAfterHook();
    }

    private function is_signature_upload_request()
    {
        $page = defined("PAGE") ? (string) PAGE : "";
        $passthru = isset($_GET["__passthru"]) ? rawurldecode((string) $_GET["__passthru"]) : "";

        return $page === "DataEntry/file_upload.php"
            || substr($page, -strlen("/DataEntry/file_upload.php")) === "/DataEntry/file_upload.php"
            || $passthru === "DataEntry/file_upload.php";
    }

    private function posted_field_name()
    {
        if (!isset($_POST["field_name"]) || !is_string($_POST["field_name"])) {
            return null;
        }

        $field = explode("-", $_POST["field_name"], 2)[0];
        if (!preg_match('/^[a-z][a-z0-9_]*$/i', $field)) {
            return null;
        }

        return $field;
    }

    private function get_configured_signature_fields($instrument)
    {
        $fields = array();
        foreach ($this->get_project_metadata() as $field => $metadata) {
            if (($metadata["form_name"] ?? null) === $instrument && $this->is_configured_signature_field($metadata)) {
                $fields[] = $field;
            }
        }
        return $fields;
    }

    private function is_configured_signature_field($metadata)
    {
        if (($metadata["element_type"] ?? null) !== "file") {
            return false;
        }
        if (!in_array($metadata["element_validation_type"] ?? null, array("signature", "enhanced_signature"), true)) {
            return false;
        }

        $annotation = isset($metadata["misc"]) ? $metadata["misc"] : ($metadata["field_annotation"] ?? "");
        $tags = ActionTagHelper::parseActionTags((string) $annotation, self::ACTIONTAG);
        return is_array($tags) && count($tags) > 0;
    }

    private function get_project_metadata()
    {
        if (class_exists("\\Design") && \Design::isDraftPreview() && !empty($this->proj->metadata_temp)) {
            return $this->proj->metadata_temp;
        }
        return $this->proj->metadata;
    }

    private function init_proj($project_id)
    {
        if ($this->proj == null) {
            $this->proj = new \Project($project_id);
            $this->project_id = $project_id;
        }
    }

    private function require_proj()
    {
        if ($this->proj == null) {
            throw new Exception($this->tt("error_project_not_initialized"));
        }
    }

    private function init_config()
    {
        $this->require_proj();
        $setting = $this->getProjectSetting("javascript-debug");
        $this->js_debug = $setting == true;
    }

    #endregion

}
