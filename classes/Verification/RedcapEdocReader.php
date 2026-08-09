<?php

namespace DE\RUB\WatermarkedSignaturesExternalModule\Verification;

/**
 * Reads an edoc through REDCap's storage abstraction without exposing bytes
 * in the verification result.
 */
class RedcapEdocReader
{
    public function read($edocId, $projectId, $maxContentsBytes = null)
    {
        $edocId = (int) $edocId;
        $projectId = (int) $projectId;
        $info = \Files::getEdocInfo($edocId, $projectId, false);
        if (!is_array($info)) {
            return array(
                'exists' => false,
                'readable' => false,
                'contents' => null,
                'mime_type' => null,
                'doc_name' => null
            );
        }
        if ($maxContentsBytes !== null
            && isset($info['doc_size'])
            && is_numeric($info['doc_size'])
            && (int) $info['doc_size'] > (int) $maxContentsBytes) {
            return array(
                'exists' => true,
                'readable' => false,
                'contents' => null,
                'mime_type' => $info['mime_type'] ?? null,
                'doc_name' => $info['doc_name'] ?? null
            );
        }

        $attributes = \Files::getEdocContentsAttributes($edocId);
        if (!is_array($attributes) || !array_key_exists(2, $attributes)) {
            return array(
                'exists' => true,
                'readable' => false,
                'contents' => null,
                'mime_type' => $info['mime_type'] ?? null,
                'doc_name' => $info['doc_name'] ?? null
            );
        }

        $contents = $attributes[2];
        if (is_object($contents) && method_exists($contents, '__toString')) {
            $contents = (string) $contents;
        }

        return array(
            'exists' => true,
            'readable' => is_string($contents),
            'contents' => is_string($contents) ? $contents : null,
            'mime_type' => isset($attributes[0]) ? (string) $attributes[0] : ($info['mime_type'] ?? null),
            'doc_name' => isset($attributes[1]) ? (string) $attributes[1] : ($info['doc_name'] ?? null)
        );
    }
}
