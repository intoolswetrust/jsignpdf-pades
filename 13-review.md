# Code Review: PR #13 -- "Extending the pades with Claude"

## 1. Security Issues

### [HIGH] Passwords stored as String, not char[]

- `BasicConfig.java:48` -- `keyStorePassword` is a `String` field. Strings are immutable and cannot be zeroed after use, leaving passwords in memory until GC. Same for `keyPassword` (:50), `pdfOwnerPwd` (:137), `pdfUserPwd` (:140).
- `TsaConfig.java:27` -- `tsaPassword` as String.
- `TrustConfig.java:25` (both modules) -- `keystorePassword` as String.
- The getters like `getKeyStorePasswordAsChars()` (`BasicConfig.java:224`) create new arrays from the retained String, so the String itself is never cleared. This is partly a JCommander limitation, but should at least be documented.

## 5. Test Coverage Gaps

### [LOW] `CERTIFICATE` TSA authentication mode is dead code

`ServerAuthentication.CERTIFICATE` is defined but never tested and never implemented in `SignerLogic.java` (only `PASSWORD` mode is handled at :222-229).

## 7. Documentation

- **[LOW]** README claims Mutual TLS support (line 10), but `CERTIFICATE` authentication is not implemented in `SignerLogic`.
