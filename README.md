# Watermarked Signatures

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.xxx.svg)](https://doi.org/10.5281/zenodo.xxx)

A REDCap EM that adds context-bound watermarks to newly captured signatures in
REDCap signature and enhanced-signature fields.

Add `@WATERMARKED-SIGNATURE` to a signature field to enable the current
technical-spike implementation. The module creates a signed field envelope on
the form or survey page, verifies it in REDCap's iframe upload receiver, renders
the watermark server-side, and records upload provenance after REDCap creates
the edoc.

The save-time one-edoc-one-binding phase and verification interfaces are not yet
implemented. See [DEV_DOCS/implementation_plan.md](DEV_DOCS/implementation_plan.md)
and [DEV_DOCS/hook_discovery.md](DEV_DOCS/hook_discovery.md).


## Release History

See [CHANGELOG.md](CHANGELOG.md) for version history and notable changes.
