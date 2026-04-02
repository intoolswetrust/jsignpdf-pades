# Code Review: PR #13 -- "Extending the pades with Claude"

## 1. Security Issues

### [HIGH] Passwords stored as String, not char[]

- `BasicConfig.java:48` -- `keyStorePassword` is a `String` field. Strings are immutable and cannot be zeroed after use, leaving passwords in memory until GC. Same for `keyPassword` (:50), `pdfOwnerPwd` (:137), `pdfUserPwd` (:140).
- `TsaConfig.java:27` -- `tsaPassword` as String.
- `TrustConfig.java:25` (both modules) -- `keystorePassword` as String.
- The getters like `getKeyStorePasswordAsChars()` (`BasicConfig.java:224`) create new arrays from the retained String, so the String itself is never cleared. This is partly a JCommander limitation, but should at least be documented.

### [MEDIUM] SHA-1 and RIPEMD-160 offered as signing algorithms

- `HashAlgorithm.java:6,10` -- SHA-1 is cryptographically broken for collision resistance, RIPEMD-160 is deprecated. Consider at minimum logging a warning when these are selected.

### [LOW] Temp files may contain sensitive PDF content

- `SignerLogic.java:305,313` -- `encryptPdf()` and `addBlankPage()` write temp files with `deleteOnExit()`. Files persist for JVM lifetime and survive crashes.

## 2. Bugs and Logic Errors

### [HIGH] TSA URL silently overrides PadesLevel

`SignerLogic.java:141-145`:
```java
if (useTsa) {
    parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
} else {
    parameters.setSignatureLevel(options.getPadesLevel().getSignatureLevel());
}
```
When a TSA URL is provided, the signature level is always forced to `BASELINE_T`, even if the user explicitly requested `BASELINE_LT` or `BASELINE_LTA`. The user's `--pades-level` flag is silently ignored. Users requesting LT/LTA levels need a TSA, yet the code downgrades them to T.

### [HIGH] LOTL sources never added to list

`TrustedCertSourcesProvider.java:72-77`:
```java
for (String url : trustConfig.getLotlUrls()) {
    LOTLSource lotlSource = new LOTLSource();
    lotlSource.setUrl(url);
    lotlSource.setCertificateSource(new CommonCertificateSource());
    // missing: lotlSources.add(lotlSource);
}
```
Custom LOTL URLs are created but **never added** to the `lotlSources` list. The `--trust-lotl-url` feature is completely broken.

### [MEDIUM] EU LOTL flag is a no-op in validator

`SignatureValidator.java:59-61` -- When `--trust-use-default-lotl` is set, it only logs a message but never actually loads the EU LOTL. The validator's `configureTrust()` does nothing with LOTL URLs either.

### [MEDIUM] Duplicate import in Main.java

`Main.java:11-12` -- `import org.apache.commons.lang3.StringUtils;` appears twice.

### [MEDIUM] Deprecated API usage

`SignerLogic.java:29` -- `org.apache.commons.lang3.text.StrSubstitutor` is deprecated since commons-lang3 3.6. Should use `org.apache.commons.text.StringSubstitutor` from `commons-text`.

### [LOW] Exit code not set on signing failure

`Main.java:61-63` -- `signFiles()` tracks `failedCount` but doesn't propagate it. The CLI exits with code 0 even when all files fail to sign.

### [LOW] Redundant password setting

`SignerLogic.java:193-196` -- `parameters.setPasswordProtection(ownerPwd.toCharArray())` is called twice inside the password encryption block (also at :181-183).

### [LOW] Font InputStream potentially leaked

`FontUtils.java:27-29` -- The `InputStream` from `getResourceAsStream()` is passed to `DSSFileFont` but never explicitly closed.

### [LOW] `encryptPdf` inconsistent error signaling

`SignerLogic.java:291` -- Method is declared `throws Exception` but uses `null` return as error signal. The caller checks for null but also wraps in try-catch. Pick one pattern.

## 3. Design / Architecture

### [MEDIUM] Dual digest algorithm options create confusion

`BasicConfig.java:59-63` -- There are two ways to set the digest algorithm: `--digest-algorithm` (DSS `DigestAlgorithm` enum) and `--hash-algorithm` (custom `HashAlgorithm` enum). `SignerLogic.java:131-133` gives `hashAlgorithm` priority. One should be removed or deprecated.

### [MEDIUM] TrustConfig duplicated between modules

`jsignpdf-pades/config/TrustConfig.java` and `validator/config/TrustConfig.java` are nearly identical. They've already drifted apart (signer does LOTL loading, validator doesn't), creating module-specific bugs.

### [LOW] PDF loaded multiple times for complex signing

When encryption, blank-page insertion, and visible signature are all enabled, the input PDF is loaded 4 separate times. Could be significant for large files.

### [LOW] `PrivateKeySignatureToken.sign()` ignores its `keyEntry` parameter

`PrivateKeySignatureToken.java:46-47` -- The `sign` method always uses the instance's `privateKey` field, ignoring the passed `DSSPrivateKeyEntry`. Misleading contract.

### [LOW] Catching `OutOfMemoryError`

`SignerLogic.java:261` -- Catching OOM is generally discouraged; JVM state is unpredictable after OOM.

## 4. Code Quality

### [LOW] Wrong artifact path for version detection

`Constants.java:43` -- Path uses `jsignpdf` but the actual artifactId is `jsignpdf-pades`. Version will always be `[UNKNOWN]`.

### [LOW] `e.printStackTrace()` in production code

`FontUtils.java:32` -- Should use a logger instead of printing to stderr.

### [LOW] Magic number 30000

`SignerLogic.java:184` -- `parameters.setContentSize(30000)` uses an unexplained magic number. Should be a named constant.

### [LOW] Mutable public static fields

`Pkcs11Initializer.java:22-23` -- `SUN_PROVIDER` and `JSIGN_PROVIDER` are public mutable statics, problematic for testing and concurrent usage.

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
- **[LOW]** README mentions Baseline-LT/LTA as features, but `SignerLogic` overrides to `BASELINE_T` whenever TSA is present, making LT/LTA effectively unusable.
- **[INFO]** AGENTS.md is well-structured and accurate for the module layout.

## Summary

| Severity | Count | Key Items |
|----------|-------|-----------|
| HIGH     | 3     | TSA overrides PadesLevel; LOTL sources never added; Passwords as Strings |
| MEDIUM   | 7     | SSRF via cert URLs; SHA-1 offered; EU LOTL no-op in validator; duplicate import; deprecated API; dual hash options; no PadesLevel tests |
| LOW      | 15    | Code quality, resource leaks, dead code, test gaps |

### Recommended fixes before merge

1. **`TrustedCertSourcesProvider.java:72-77`** -- Add `lotlSources.add(lotlSource)` to fix dead `--trust-lotl-url`
2. **`SignerLogic.java:141-145`** -- Respect user's PadesLevel when TSA is set (only override to T if level is B)
3. **`SignatureValidator.java:59-61`** -- Actually implement LOTL loading in the validator, or remove the flag
4. **`Main.java:61-63`** -- Propagate signing failures to exit code
