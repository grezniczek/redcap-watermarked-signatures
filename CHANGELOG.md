# Changelog

| Version | Description |
|---------|-------------|
| 1.0.0   | Initial release. |
| 1.0.1   | Security hardening and PHP compatibility cleanup. |
| 1.0.2   | Added option to clear a custom image; updated documentation; added type annotations to the code. |
| 1.0.3   | Added optional field-specific REF marks through `@WATERMARKED-SIGNATURE="MARK"`; limited new project REF values to 20 characters; retained v1.0.2 verification compatibility for new signatures. |
| 1.0.4   | Added encrypted, binding-authenticated upload-time IP provenance for e-Consent and data-entry signatures; e-Consent captures receive a diagnostic comparison against REDCap's stored e-Consent IP. Plaintext administrator disclosure is gated by the Database Query Tool. Made global verification available to authorized Control Center dashboard users. |
