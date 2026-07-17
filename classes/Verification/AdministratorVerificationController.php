<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Verification;

use Throwable;
use DE\RUB\WatermarkedSignaturesExternalModule\Crypto\ReferenceGenerator;

/**
 * Administrator-only adapter for global exact signature verification.
 */
class AdministratorVerificationController
{
    private $repository;
    private $service;

    public function __construct($repository, $service)
    {
        if (!is_object($repository)
            || !method_exists($repository, 'findDiagnosticEventsByEdocId')
            || !method_exists($repository, 'findRecordRenameEventsByCurrentRecord')) {
            throw new \InvalidArgumentException('The repository must provide diagnostic and record-rename lookup methods.');
        }
        if (!is_object($service) || !method_exists($service, 'verify')) {
            throw new \InvalidArgumentException('The verification service must provide verify().');
        }
        $this->repository = $repository;
        $this->service = $service;
    }

    public function verify($captureReference)
    {
        $normalizedReference = ReferenceGenerator::normalizeCaptureReference($captureReference);
        if ($normalizedReference === null) {
            return $this->present($this->service->verify($captureReference, null), array(), 'capture_reference', $captureReference);
        }

        try {
            $result = $this->service->verify($normalizedReference, null);
            $upload = isset($result['upload']) && is_array($result['upload']) ? $result['upload'] : array();
            $edocId = isset($upload['edoc_id']) && is_numeric($upload['edoc_id'])
                ? (int) $upload['edoc_id']
                : 0;
            $diagnostics = $edocId > 0
                ? $this->repository->findDiagnosticEventsByEdocId($edocId)
                : array();
            return $this->present($result, $this->appendRecordRenameDiagnostics($diagnostics, $result), 'capture_reference', $normalizedReference);
        } catch (Throwable $exception) {
            return $this->technicalFailure($normalizedReference, 'capture_reference', $normalizedReference);
        }
    }

    public function verifyEdocId($edocId)
    {
        if ((!is_int($edocId) && !(is_string($edocId) && ctype_digit($edocId))) || (int) $edocId < 1) {
            return $this->invalidEdocId($edocId);
        }
        $edocId = (int) $edocId;

        try {
            $diagnostics = $this->repository->findDiagnosticEventsByEdocId($edocId);
            $upload = $this->repository->findUploadByEdocId($edocId);
            if ($upload === null) {
                return $this->unknownEdocId($edocId, $diagnostics);
            }
            $captureReference = ReferenceGenerator::normalizeCaptureReference($upload['capture_ref'] ?? null);
            if ($captureReference === null) {
                return $this->technicalFailure(null, 'edoc_id', $edocId, $diagnostics);
            }
            $result = $this->service->verify($captureReference, null);
            return $this->present($result, $this->appendRecordRenameDiagnostics($diagnostics, $result), 'edoc_id', $edocId);
        } catch (Throwable $exception) {
            return $this->technicalFailure(null, 'edoc_id', $edocId);
        }
    }

    private function present($result, $diagnostics, $lookupType, $lookupValue)
    {
        $upload = isset($result['upload']) && is_array($result['upload']) ? $result['upload'] : array();
        $binding = isset($result['binding']) && is_array($result['binding']) ? $result['binding'] : array();
        $details = array();

        $this->copy($details, $upload, array(
            'capture_ref', 'context_ref', 'anchor', 'capture_origin',
            'capture_username', 'captured_at', 'edoc_id', 'file_sha256',
            'watermark_version'
        ));
        $this->copy($details, $binding, array(
            'event_id', 'instrument', 'field', 'repeat_type',
            'repeat_instrument', 'repeat_instance', 'bound_at', 'save_origin',
            'save_username'
        ));
        $details['record_id'] = $result['current_record_id'] ?? ($binding['record_id'] ?? null);
        $this->copyMapped($details, $upload, array(
            'pid' => 'upload_project_id',
            '_project_id' => 'upload_log_project_id',
            '_log_id' => 'upload_log_id'
        ));
        $this->copyMapped($details, $binding, array(
            'pid' => 'binding_project_id',
            '_project_id' => 'binding_log_project_id',
            '_log_id' => 'binding_log_id'
        ));

        return array(
            'status' => $result['status'] ?? 'incomplete',
            'binding_state' => $result['binding_state'] ?? 'unknown',
            'integrity' => $result['integrity'] ?? 'not_checked',
            'current_state' => $result['current_state'] ?? 'unknown',
            'capture_ref' => $result['capture_ref'] ?? null,
            'checks' => isset($result['checks']) && is_array($result['checks']) ? $result['checks'] : array(),
            'issues' => isset($result['issues']) && is_array($result['issues']) ? $result['issues'] : array(),
            'edoc' => isset($result['edoc']) && is_array($result['edoc']) ? $result['edoc'] : null,
            'details' => $details,
            'diagnostics' => $this->presentDiagnostics($diagnostics),
            'lookup_type' => $lookupType,
            'lookup_value' => $lookupValue
        );
    }

    private function presentDiagnostics($diagnostics)
    {
        if (!is_array($diagnostics)) {
            return array();
        }

        $presented = array();
        foreach ($diagnostics as $diagnostic) {
            if (!is_array($diagnostic)) {
                continue;
            }
            $entry = array();
            $this->copy($entry, $diagnostic, array(
                'log_id', 'timestamp', 'username', 'project_id', 'record',
                'message', 'edoc_id', 'capture_ref', 'context_ref', 'anchor',
                'event_id', 'instrument', 'field', 'capture_origin',
                'capture_username', 'save_origin', 'save_username', 'bound_at',
                'technical_message', 'original_log_id', 'binding_log_id',
                'previous_record_id', 'rename_origin', 'rename_username', 'renamed_at'
            ));
            if (!empty($entry)) {
                $presented[] = $entry;
            }
        }
        return $presented;
    }

    private function appendRecordRenameDiagnostics($diagnostics, $result)
    {
        if (!is_array($diagnostics)) {
            $diagnostics = array();
        }
        $binding = isset($result['binding']) && is_array($result['binding']) ? $result['binding'] : array();
        $projectId = $binding['pid'] ?? null;
        $currentRecordId = $result['current_record_id'] ?? null;
        if (!is_numeric($projectId) || (int) $projectId < 1 || !is_scalar($currentRecordId) || (string) $currentRecordId === '') {
            return $diagnostics;
        }

        $renames = $this->repository->findRecordRenameEventsByCurrentRecord((int) $projectId, (string) $currentRecordId);
        if (!is_array($renames) || empty($renames)) {
            return $diagnostics;
        }

        $diagnostics = array_merge($diagnostics, $renames);
        usort($diagnostics, function ($left, $right) {
            return ((int) ($left['log_id'] ?? 0)) <=> ((int) ($right['log_id'] ?? 0));
        });
        return $diagnostics;
    }

    private function copy(&$target, $source, $fields)
    {
        foreach ($fields as $field) {
            if (array_key_exists($field, $source)) {
                $target[$field] = $source[$field];
            }
        }
    }

    private function copyMapped(&$target, $source, $fields)
    {
        foreach ($fields as $sourceField => $targetField) {
            if (array_key_exists($sourceField, $source)) {
                $target[$targetField] = $source[$sourceField];
            }
        }
    }

    private function invalidEdocId($edocId)
    {
        return array(
            'status' => 'invalid_edoc_id',
            'binding_state' => 'unknown',
            'integrity' => 'not_checked',
            'current_state' => 'unknown',
            'capture_ref' => null,
            'checks' => array(),
            'issues' => array('invalid_edoc_id'),
            'edoc' => null,
            'details' => array(),
            'diagnostics' => array(),
            'lookup_type' => 'edoc_id',
            'lookup_value' => $edocId
        );
    }

    private function unknownEdocId($edocId, $diagnostics)
    {
        return array(
            'status' => 'unknown',
            'binding_state' => 'unknown',
            'integrity' => 'not_checked',
            'current_state' => 'unknown',
            'capture_ref' => null,
            'checks' => array(),
            'issues' => array(),
            'edoc' => null,
            'details' => array(),
            'diagnostics' => $this->presentDiagnostics($diagnostics),
            'lookup_type' => 'edoc_id',
            'lookup_value' => $edocId
        );
    }

    private function technicalFailure($captureReference, $lookupType, $lookupValue, $diagnostics = array())
    {
        return array(
            'status' => 'invalid',
            'binding_state' => 'unknown',
            'integrity' => 'invalid',
            'current_state' => 'unknown',
            'capture_ref' => $captureReference,
            'checks' => array(),
            'issues' => array('log_integrity_error'),
            'edoc' => null,
            'details' => array(),
            'diagnostics' => $this->presentDiagnostics($diagnostics),
            'lookup_type' => $lookupType,
            'lookup_value' => $lookupValue
        );
    }
}
