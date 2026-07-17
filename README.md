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

## Optional public project reference

The project-level **Public project reference** setting may contain a short
public acronym or identifier (1–30 ASCII letters, digits, spaces, dots,
hyphens, underscores, or slashes). When set, every newly captured signature
visibly includes `REF:<reference>` in its footer.

This is a presentation aid only: it is not the REDCap project ID and does not
replace the cryptographic anchor. It is snapshotted at capture time, so later
setting changes do not alter existing images or provenance. Because the value
is visible in the signature image, including exports and screenshots, leave it
blank unless disclosing that reference is appropriate for the project. Do not
use a project title or other sensitive information.

The footer labels the server-generated UTC capture time as `TS:`. It is a
timestamp for the image capture process, not an assertion of signer identity
or a qualified signing time.

See [DEV_DOCS/implementation_plan.md](DEV_DOCS/implementation_plan.md) and
[DEV_DOCS/hook_discovery.md](DEV_DOCS/hook_discovery.md) for the implementation
and verification design.


## Release History

See [CHANGELOG.md](CHANGELOG.md) for version history and notable changes.
