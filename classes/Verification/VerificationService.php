<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Verification;

use Throwable;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\Anchor;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\BindingMac;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\KeyDerivation;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;
use DE\RUB\WatermarkedSignaturesExternalModule\Storage\LogRepository;

/**
 * UI-independent exact-lookup verification engine.
 */
class VerificationService
{
    private $repository;
    private $bindingMac;
    private $edocReader;
    private $currentValueReader;

    private static $uploadBindingFields = array(
        'v',
        'anchor',
        'capture_ref',
        'context_ref',
        'record_ref',
        'project_reference',
        'capture_origin',
        'capture_username',
        'edoc_id',
        'pid',
        'event_id',
        'instrument',
        'field',
        'file_sha256',
        'watermark_version'
    );

    public function __construct(
        LogRepository $repository,
        BindingMac $bindingMac,
        $edocReader,
        $currentValueReader
    ) {
        if (!is_object($edocReader) || !method_exists($edocReader, 'read')) {
            throw new \InvalidArgumentException('The edoc reader must provide read().');
        }
        if (!is_object($currentValueReader) || !method_exists($currentValueReader, 'read')) {
            throw new \InvalidArgumentException('The current-value reader must provide read().');
        }
        $this->repository = $repository;
        $this->bindingMac = $bindingMac;
        $this->edocReader = $edocReader;
        $this->currentValueReader = $currentValueReader;
    }

    /**
     * @param string $captureReference Full high-entropy capture reference.
     * @param int|null $projectId Restrict to one project, or null for an administrator lookup.
     */
    public function verify($captureReference, $projectId = null)
    {
        $result = $this->emptyResult($captureReference);
        if (!ReferenceGenerator::isCaptureReference($captureReference)) {
            $result['status'] = 'invalid_reference';
            $result['issues'][] = 'invalid_capture_reference';
            return $result;
        }
        if ($projectId !== null && (!is_int($projectId) || $projectId < 1)) {
            throw new \InvalidArgumentException('Project ID must be a positive integer or null.');
        }

        $upload = $this->repository->findUploadByCaptureReference($captureReference, $projectId);
        if ($upload === null) {
            $result['status'] = 'unknown';
            return $result;
        }

        $result['upload'] = $upload;
        $result['binding_state'] = 'unbound';
        $this->checkUploadProject($result, $upload, $projectId);
        $result['checks']['anchor'] = $this->verifyAnchor($upload);
        if (!$result['checks']['anchor']) {
            $this->addIssue($result, 'anchor_mismatch');
        }

        $edocId = $this->positiveInteger($upload['edoc_id'] ?? null);
        $uploadProjectId = $this->positiveInteger($upload['pid'] ?? null);
        if ($edocId === null || $uploadProjectId === null) {
            $this->addIssue($result, 'invalid_upload_provenance');
        } else {
            $this->checkEdoc($result, $upload, $edocId, $uploadProjectId);
        }

        $binding = $edocId === null ? null : $this->repository->findBindingByEdocId($edocId);
        if ($binding === null) {
            $result['status'] = 'unbound';
            $result['integrity'] = empty($result['issues']) ? 'valid' : 'invalid';
            return $result;
        }

        $result['binding'] = $binding;
        $result['binding_state'] = 'bound';
        $result['current_record_id'] = $this->currentRecordId($binding);
        try {
            $result['checks']['binding_mac'] = $this->bindingMac->verify($binding);
        } catch (Throwable $exception) {
            $result['checks']['binding_mac'] = false;
        }
        if (!$result['checks']['binding_mac']) {
            $this->addIssue($result, 'binding_mac_mismatch');
        }

        $result['checks']['binding_upload'] = $this->bindingMatchesUpload($binding, $upload);
        if (!$result['checks']['binding_upload']) {
            $this->addIssue($result, 'binding_upload_mismatch');
        }

        $bindingAnchorValid = $this->verifyAnchor($binding);
        if (!$bindingAnchorValid) {
            $result['checks']['anchor'] = false;
            $this->addIssue($result, 'anchor_mismatch');
        }

        if ($result['checks']['binding_mac']
            && $result['checks']['binding_upload']
            && $result['checks']['anchor']) {
            $this->checkCurrentField($result, $binding, $edocId);
        }

        return $this->finalizeBoundResult($result);
    }

    private function emptyResult($captureReference)
    {
        return array(
            'status' => null,
            'binding_state' => 'unknown',
            'integrity' => 'not_checked',
            'current_state' => 'unknown',
            'capture_ref' => is_string($captureReference) ? $captureReference : null,
            'upload' => null,
            'binding' => null,
            'current_record_id' => null,
            'edoc' => null,
            'checks' => array(
                'binding_mac' => null,
                'binding_upload' => null,
                'anchor' => null,
                'edoc_exists' => null,
                'file_digest' => null,
                'current_field' => null
            ),
            'issues' => array()
        );
    }

    private function checkUploadProject(&$result, $upload, $requestedProjectId)
    {
        $payloadProjectId = $this->positiveInteger($upload['pid'] ?? null);
        $logProjectId = $this->positiveInteger($upload['_project_id'] ?? null);
        if (($logProjectId !== null && $payloadProjectId !== $logProjectId)
            || ($requestedProjectId !== null && $payloadProjectId !== $requestedProjectId)) {
            $this->addIssue($result, 'upload_project_mismatch');
        }
    }

    private function checkEdoc(&$result, $upload, $edocId, $projectId)
    {
        try {
            $edoc = $this->edocReader->read($edocId, $projectId);
        } catch (Throwable $exception) {
            $result['edoc'] = array('exists' => null, 'readable' => false);
            $this->addIssue($result, 'edoc_unreadable');
            return;
        }
        if (!is_array($edoc)) {
            $result['edoc'] = array('exists' => null, 'readable' => false);
            $this->addIssue($result, 'edoc_unreadable');
            return;
        }

        $exists = ($edoc['exists'] ?? false) === true;
        $readable = ($edoc['readable'] ?? false) === true;
        $result['edoc'] = array(
            'exists' => $exists,
            'readable' => $readable,
            'mime_type' => $edoc['mime_type'] ?? null,
            'doc_name' => $edoc['doc_name'] ?? null
        );
        $result['checks']['edoc_exists'] = $exists;
        if (!$exists) {
            $this->addIssue($result, 'edoc_missing');
            return;
        }
        if (!$readable || !isset($edoc['contents']) || !is_string($edoc['contents'])) {
            $this->addIssue($result, 'edoc_unreadable');
            return;
        }

        $expectedDigest = isset($upload['file_sha256']) ? (string) $upload['file_sha256'] : '';
        $actualDigest = hash('sha256', $edoc['contents']);
        $result['checks']['file_digest'] = preg_match('/^[a-f0-9]{64}$/D', $expectedDigest) === 1
            && hash_equals($expectedDigest, $actualDigest);
        if (!$result['checks']['file_digest']) {
            $this->addIssue($result, 'file_digest_mismatch');
        }
    }

    private function checkCurrentField(&$result, $binding, $edocId)
    {
        $currentRecordId = $this->currentRecordId($binding);
        if ($currentRecordId === null) {
            $this->addIssue($result, 'current_field_unreadable');
            return;
        }

        // REDCap preserves the immutable record_id in the binding payload but
        // updates the EM log row's indexed record column when a record is
        // renamed. Use that current value for the live field comparison.
        $currentBinding = $binding;
        $currentBinding['record_id'] = $currentRecordId;
        try {
            $currentValue = $this->currentValueReader->read($currentBinding);
        } catch (Throwable $exception) {
            $this->addIssue($result, 'current_field_unreadable');
            return;
        }

        $currentEdocId = $this->positiveInteger($currentValue);
        $isCurrent = $currentEdocId !== null && $currentEdocId === (int) $edocId;
        $result['checks']['current_field'] = $isCurrent;
        $result['current_state'] = $isCurrent ? 'current' : 'historical';
    }

    private function currentRecordId($binding)
    {
        if (!is_array($binding)) {
            return null;
        }
        $recordId = $binding['_current_record_id'] ?? ($binding['record_id'] ?? null);
        if (!is_scalar($recordId) || (string) $recordId === '') {
            return null;
        }
        return (string) $recordId;
    }

    private function finalizeBoundResult($result)
    {
        $invalidIssues = array(
            'invalid_upload_provenance',
            'upload_project_mismatch',
            'binding_mac_mismatch',
            'binding_upload_mismatch',
            'anchor_mismatch',
            'file_digest_mismatch'
        );
        $incompleteIssues = array('edoc_missing', 'edoc_unreadable', 'current_field_unreadable');

        if ($this->containsAny($result['issues'], $invalidIssues)) {
            $result['status'] = 'invalid';
            $result['integrity'] = 'invalid';
        } elseif ($this->containsAny($result['issues'], $incompleteIssues)
            || $result['checks']['current_field'] === null) {
            $result['status'] = 'incomplete';
            $result['integrity'] = 'incomplete';
        } elseif ($result['checks']['current_field']) {
            $result['status'] = 'valid_current';
            $result['integrity'] = 'valid';
        } else {
            $result['status'] = 'valid_historical';
            $result['integrity'] = 'valid';
        }
        return $result;
    }

    private function verifyAnchor($event)
    {
        $required = array('watermark_version', 'pid', 'event_id', 'instrument', 'field', 'anchor');
        foreach ($required as $field) {
            if (!array_key_exists($field, $event)) {
                return false;
            }
        }
        $scope = array(
            'v' => (int) $event['watermark_version'],
            'pid' => (int) $event['pid'],
            'event_id' => (int) $event['event_id'],
            'instrument' => (string) $event['instrument'],
            'field' => (string) $event['field']
        );
        $expected = Anchor::create($scope, KeyDerivation::derive(KeyDerivation::ANCHOR_INFO));
        return is_string($event['anchor']) && hash_equals($expected, $event['anchor']);
    }

    private function bindingMatchesUpload($binding, $upload)
    {
        $bindingProjectId = $this->positiveInteger($binding['_project_id'] ?? null);
        if ($bindingProjectId !== null
            && $bindingProjectId !== $this->positiveInteger($binding['pid'] ?? null)) {
            return false;
        }
        foreach (self::$uploadBindingFields as $field) {
            if (!array_key_exists($field, $binding)
                || !array_key_exists($field, $upload)
                || $binding[$field] !== $upload[$field]) {
                return false;
            }
        }
        return true;
    }

    private function positiveInteger($value)
    {
        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            return null;
        }
        $integer = (int) $value;
        return $integer > 0 ? $integer : null;
    }

    private function addIssue(&$result, $issue)
    {
        if (!in_array($issue, $result['issues'], true)) {
            $result['issues'][] = $issue;
        }
    }

    private function containsAny($issues, $candidates)
    {
        return count(array_intersect($issues, $candidates)) > 0;
    }
}
