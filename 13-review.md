# Code Review: PR #13 -- "Extending the pades with Claude"

## 1. Security Issues

### [HIGH] Passwords stored as String, not char[]

- `BasicConfig.java:48` -- `keyStorePassword` is a `String` field. Strings are immutable and cannot be zeroed after use, leaving passwords in memory until GC. Same for `keyPassword` (:50), `pdfOwnerPwd` (:137), `pdfUserPwd` (:140).
- `TsaConfig.java:27` -- `tsaPassword` as String.
- `TrustConfig.java:25` (both modules) -- `keystorePassword` as String.
- The getters like `getKeyStorePasswordAsChars()` (`BasicConfig.java:224`) create new arrays from the retained String, so the String itself is never cleared. This is partly a JCommander limitation, but should at least be documented.

### [MEDIUM] EU LOTL flag is a no-op in validator

`SignatureValidator.java:59-61` -- When `--trust-use-default-lotl` is set, it only logs a message but never actually loads the EU LOTL. The validator's `configureTrust()` does nothing with LOTL URLs either.

## 3. Design / Architecture

### [MEDIUM] TrustConfig duplicated between modules

`jsignpdf-pades/config/TrustConfig.java` and `validator/config/TrustConfig.java` are nearly identical. They've already drifted apart (signer does LOTL loading, validator doesn't), creating module-specific bugs.

## 4. Code Quality

## 5. Test Coverage Gaps

### [MEDIUM] No test for PadesLevel values other than BASELINE_B

All signing tests use the default. No tests for `BASELINE_T` (without TSA), `BASELINE_LT`, or `BASELINE_LTA`. The TSA-overriding bug would be caught by such tests.

### [MEDIUM] No test for expired certificate signing failure

`TestConstants` defines an `EXPIRED` key but no test verifies signing with it fails.

### [LOW] Temp files outside JUnit's TempDir management

`SigningTestBase.java:48-49` -- Creates temp files via `File.createTempFile` instead of using `@TempDir`.

### [LOW] No negative test for validator with corrupted PDF

Validator tests only use well-formed PDFs.

### [LOW] `CERTIFICATE` TSA authentication mode is dead code

`ServerAuthentication.CERTIFICATE` is defined but never tested and never implemented in `SignerLogic.java` (only `PASSWORD` mode is handled at :222-229).

## 6. Dependencies

- **[LOW]** Deprecated `StrSubstitutor` from commons-lang3 -- use `commons-text` or inline replacement.
- **[INFO]** DejaVuSans.ttf bundled -- Adds binary size. License (Bitstream Vera / public domain) is fine but the license file should be included.
- **[INFO]** Dependency versions look healthy -- DSS 6.2, BouncyCastle 1.80, PDFBox 3.0.7, JUnit 5.12.2.

## 7. Documentation

- **[LOW]** README claims Mutual TLS support (line 10), but `CERTIFICATE` authentication is not implemented in `SignerLogic`.

### Recommended fixes before merge

3. **`SignatureValidator.java:59-61`** -- Actually implement LOTL loading in the validator, or remove the flag
