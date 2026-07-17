# Watermarked Signatures

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.xxx.svg)](https://doi.org/10.5281/zenodo.xxx)

A REDCap EM that adds context-bound watermarks to newly captured signatures in
REDCap signature and enhanced-signature fields.

## Requirements

REDCap 17.3.0 or later.

Add `@WATERMARKED-SIGNATURE` to a signature field to enable watermarking. The
module creates a signed field envelope on the form or survey page, verifies it
in REDCap's iframe upload receiver, renders the watermark server-side, records
upload provenance after REDCap creates the edoc, and binds the saved signature
to its authoritative REDCap context.

The project page verifies exact capture references within the caller's
form-level and DAG access. The Control Center page provides exact lookup by
capture reference or edoc ID for REDCap administrators.

## Retention

Successful bindings, record-rename events, and serious errors are retained.
Unbound upload provenance is purged daily after 90 days by default. Set the
project setting **Retain unbound signature-upload provenance for this many days**
to `0` to disable automatic purging.

See [DEV_DOCS/implementation_plan.md](DEV_DOCS/implementation_plan.md) and
[DEV_DOCS/hook_discovery.md](DEV_DOCS/hook_discovery.md) for the implementation
and verification design.


## Release History

See [CHANGELOG.md](CHANGELOG.md) for version history and notable changes.
