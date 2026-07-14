# EU LOTL Official Journal (OJ) keystore

`eu-oj-keystore.p12` validates the **signature of the EU List of Trusted Lists (LOTL)** itself
(`LOTLSource.setCertificateSource(...)`). It is *not* a trust anchor for document signers — that is
`--trust-keystore-file` / `--trust-certificate-file`.

- **Type:** PKCS12  **Password:** `dss-password` (matches the DSS demonstrations keystore convention)
- **Loaded by:** `TrustedCertSourcesProvider.ojKeystoreCertificateSource()` (constant `OJ_KEYSTORE_RESOURCE`)
- **Override at runtime:** `--trust-oj-keystore-file` / `--trust-oj-keystore-password`

## Current file

Sourced from the `dss-demonstrations` repository, tag `6.4+20260415` (post the April-2026 OJ rotation). It
holds the EUROPEAN COMMISSION qualified signer certificates (organization + named statutory staff) that sign
the EU LOTL — all `trustedCertEntry`, no private keys. DSS follows the OJ pivot chain from these anchors, so
expired/legacy entries may legitimately remain.

## Refreshing (release checklist)

Refresh when the OJ re-issues the LOTL signing certificates (roughly every few years; pivot support absorbs
the more frequent changes).

1. Copy the keystore from a matching `dss-demonstrations` tag.
2. Verify the contained signer certificates (subjects / validity) against the OJ notice.
3. Keep the path / type PKCS12 / password `dss-password`, or update the `OJ_KEYSTORE_*` constants.
4. Update `TrustedCertSourcesProvider.DEFAULT_OJ_URL` to the matching OJ notice URL.
