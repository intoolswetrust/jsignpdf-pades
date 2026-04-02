# Code Review: PR #13 -- "Extending the pades with Claude"

## 1. Security Issues

### [HIGH] Passwords stored as String, not char[]

- `BasicConfig.java:48` -- `keyStorePassword` is a `String` field. Strings are immutable and cannot be zeroed after use, leaving passwords in memory until GC. Same for `keyPassword` (:50), `pdfOwnerPwd` (:137), `pdfUserPwd` (:140).
- `TsaConfig.java:27` -- `tsaPassword` as String.
- `TrustConfig.java:25` (both modules) -- `keystorePassword` as String.
- The getters like `getKeyStorePasswordAsChars()` (`BasicConfig.java:224`) create new arrays from the retained String, so the String itself is never cleared. This is partly a JCommander limitation, but should at least be documented.

### [MEDIUM] EU LOTL flag is a no-op in validator

`SignatureValidator.java:59-61` -- When `--trust-use-default-lotl` is set, it only logs a message but never actually loads the EU LOTL. The validator's `configureTrust()` does nothing with LOTL URLs either.

## 5. Test Coverage Gaps

### [MEDIUM] No test for PadesLevel values other than BASELINE_B

All signing tests use the default. No tests for `BASELINE_T` (without TSA), `BASELINE_LT`, or `BASELINE_LTA`. The TSA-overriding bug would be caught by such tests.

### [LOW] No negative test for validator with corrupted PDF

Validator tests only use well-formed PDFs.

### [LOW] `CERTIFICATE` TSA authentication mode is dead code

`ServerAuthentication.CERTIFICATE` is defined but never tested and never implemented in `SignerLogic.java` (only `PASSWORD` mode is handled at :222-229).

## 7. Documentation

- **[LOW]** README claims Mutual TLS support (line 10), but `CERTIFICATE` authentication is not implemented in `SignerLogic`.
