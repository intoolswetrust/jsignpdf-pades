# Java 17 Migration Plan — jsignpdf-pades

## Current State

- `pom.xml` sets `<maven.compiler.release>11</maven.compiler.release>`
- Release profile enforces `requireJavaVersion` = `[11,12)`
- `maven-compiler-plugin` 3.10.1 (compatible with JDK 17; no change required)
- All runtime dependencies already support Java 17:
  - DSS 6.2, PDFBox 3.0.7, BouncyCastle 1.80, commons-lang3 3.20.0, commons-io 2.21.0, JUnit 5.12.2
- Three modules: `common`, `jsignpdf-pades`, `validator`, plus `distribution` assembly
- Dev environment already runs JDK 21, so the code builds today — only declared targets need updating

## Goals

1. Compile bytecode with `--release 17` across all modules
2. Require JDK 17+ at runtime (the produced JARs must not be consumable by JDK 11 users anymore)
3. Keep behaviour unchanged — no functional changes, no new features
4. Adopt a small, low-risk subset of 12–17 language features where they clearly improve readability

## Phase 1 — Build/Config Changes (mandatory)

### 1.1 Parent `pom.xml`
- [ ] Change `<maven.compiler.release>11</maven.compiler.release>` → `17`
- [ ] Change the `release` profile enforcer rule `<version>[11,12)</version>` → `[17,18)`)
- [ ] Bump `maven-compiler-plugin` from 3.10.1 → 3.13.0 (better JDK 17+ support, fixes a few annotation-processing edge cases)
- [ ] Bump `maven-source-plugin` from 3.2.1 → 3.3.1 (JDK 17 compatibility)
- [ ] Consider bumping `maven-jar-plugin`, `maven-dependency-plugin`, `maven-shade-plugin`, `maven-assembly-plugin` to their latest releases for consistent JDK 17 behaviour

### 1.2 GitHub Actions / CI
- [ ] Update the CI workflow's `setup-java` step(s) to `java-version: '17'`
- [ ] If a matrix is used, drop the 11 entry; optionally add 17 + 21 to test LTS versions

### 1.3 README / docs
- [ ] Update `README.md` "Requirements" section: "Java 11 or later" → "Java 17 or later"
- [ ] Update `AGENTS.md` similarly ("Java 11+ required")

### 1.4 Distribution module
- [ ] Check `distribution/` assembly descriptor for any hardcoded Java version references

## Phase 2 — Source-Code Modernisation (optional, one commit per item)

These are small cleanups that become available at 17 and noticeably improve readability. Each is independent — cherry-pick what you want.

### 2.1 Replace deprecated `StrSubstitutor` (already on the backlog, now is a good moment)
- `SignerLogic.java:29` imports `org.apache.commons.lang3.text.StrSubstitutor` which is deprecated since commons-lang3 3.6.
- Replace with Java 17's built-in pattern:
  ```java
  // Simple alternative without extra dependency:
  String result = template;
  for (var e : replacements.entrySet()) {
      result = result.replace("${" + e.getKey() + "}", e.getValue());
  }
  ```

### 2.2 Text blocks for multi-line strings
- Good fit: test code in `SignerLogicValidationTest`, any XML/JSON fixtures, README snippets embedded in code.
- Not critical in production code — the codebase has few multi-line literals.

### 2.3 `var` for local variables with obvious types
- Candidate call sites: `SignerLogic.signFile()` (lots of DSS types with long names), `PdfSignatureValidator.validate()` in tests.
- Style rule of thumb: use `var` only when the initialiser makes the type obvious (e.g. `var ks = KeyStore.getInstance("JKS")`).

### 2.4 Pattern matching for `instanceof` (Java 16+)
- `PdfSignatureValidator.java` test helper has several `if (x instanceof Foo) { Foo f = (Foo) x; ... }` patterns — collapse to `if (x instanceof Foo f) { ... }`.
- `SignerLogic.java` has none; skip.

### 2.5 `switch` expressions (Java 14+)
- `CertificationLevel.toDssCertificationPermission()` is a classic `switch` statement returning values — convert to switch expression:
  ```java
  return switch (this) {
      case CERTIFIED_NO_CHANGES_ALLOWED -> CertificationPermission.NO_CHANGE_PERMITTED;
      case CERTIFIED_FORM_FILLING      -> CertificationPermission.MINIMAL_CHANGES_PERMITTED;
      case CERTIFIED_FORM_FILLING_AND_ANNOTATIONS -> CertificationPermission.CHANGES_PERMITTED;
      default -> null;
  };
  ```

### 2.6 Records for simple data carriers
- No obvious candidates in `main/`. In tests, `PdfSignatureValidator.ValidationResult` is an all-public-fields DTO — it could become a record, but that would break the mutation pattern currently used by the extractor methods. **Skip unless the extractor is refactored too.**

### 2.7 Lambda for `HostnameVerifier`
- `SSLInitializer.java:70` uses an anonymous `HostnameVerifier` — already a one-method interface, convert to lambda:
  ```java
  HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
  ```

## Phase 3 — Things to WATCH OUT FOR (potential breakages)

### 3.1 Strong encapsulation of JDK internals (JEP 403, Java 17)
- The code uses `sun.security.pkcs11.SunPKCS11` via reflection in `Pkcs11Initializer.java:66`.
  - This package is **exported** by the `jdk.crypto.cryptoki` module at run time (`java.security.Provider` usage is allowed), so no `--add-opens` should be needed.
  - Verify with a manual smoke test using a software PKCS#11 token (SoftHSM) or the existing unit tests that exercise PKCS#11 init paths.
- System properties `sun.security.ssl.allowUnsafeRenegotiation` / `sun.security.ssl.allowLegacyHelloMessages` (used in `SSLInitializer.java`) still exist in JDK 17 — no change.

### 3.2 `com.sun.net.httpserver.HttpServer` (tests)
- `EmbeddedTsaServer.java` imports `com.sun.net.httpserver.*`. This is part of the `jdk.httpserver` module and is supported on JDK 17. No change required.

### 3.3 `SecurityManager` deprecation
- JDK 17 deprecates `SecurityManager` for removal. The project does not install or rely on one — no action needed.

### 3.4 DSS and third-party runtime behaviour
- DSS 6.2 is tested on JDK 17. No known issues.
- Apache HttpClient 5 (bundled via DSS) works on JDK 17.
- Check the PDFBox 3.0.7 release notes for any JDK 17-specific fixes you might want.

### 3.5 Maven Shade + `module-info.class`
- The parent POM already excludes `**/module-info.class` in the shade configuration — good. No change needed.

## Phase 4 — Validation

1. **Clean build:** `mvn clean verify` on JDK 17 — all 106 tests should pass.
2. **Fat-JAR smoke test:** run the `demo/test-readme-commands.sh` script against the freshly built JARs.
3. **PKCS#11 smoke test** (manual): if you have a test HSM or SoftHSM available, sign a PDF using the PKCS#11 provider to confirm the `SunPKCS11` reflection path still works.
4. **Run on a clean JDK 17** (Temurin 17.0.x) VM or container — not just on the dev JDK 21 — to rule out inadvertent use of a 18+ API.
5. **Cross-check the shaded JAR** manifest `Build-Jdk` and class versions (`unzip -p jar target/classes/X.class | file -` → should report class version 61 = JDK 17).

## Phase 5 — Follow-ups (not strictly migration)

- Consider moving to Java 21 LTS in a separate follow-up PR once 17 is stable on main.
- After 17, `Runtime.Version` and the newer `HttpClient` (JEP 321, Java 11+) could replace some Apache HttpClient usages, but that's out of scope here.

## Rollback Plan

The change is non-destructive: revert the three `pom.xml` edits (release target, enforcer range, plugin versions) and re-build. No database schema / API contract / on-disk format is affected by this migration.

## Estimated Effort

- Phase 1 (mandatory): ~30 minutes of POM edits + one CI run
- Phase 2 (optional): ~1–2 hours total if all items are adopted
- Phase 3 (verification): ~1 hour of manual smoke testing including PKCS#11

Total: a single afternoon for a cautious full migration, less if Phase 2 is skipped.
