# AGENTS.md - AI Agent Guidelines for jsignpdf-pades

## Project Overview

jsignpdf-pades is a Java CLI application for PAdES PDF signing and validation. It consists of independent Maven modules built on the EU DSS library and Apache PDFBox.

## Module Structure

```
jsignpdf-pades/             # Parent POM (groupId: com.github.kwart.jsign)
  jsignpdf-pades/           # Signing module (artifactId: jsignpdf-pades)
  validator/                # Validation module (artifactId: jsignpdf-pades-validator)
  distribution/             # ZIP distribution assembly
```

Modules are independent - the validator does not depend on the signing module.

## Package Structure

- Signing: `com.github.intoolswetrust.jsignpdf.pades`
- Validator: `com.github.intoolswetrust.jsignpdf.pades.validator`

## Build

```bash
mvn clean test                    # Build and test all modules
mvn package                       # Build fat JARs
```

Java 11+ required. Tests use JUnit 5.

## Key Classes

### Signing Module

| Class | Role |
|-------|------|
| `Main` | CLI entry point, argument parsing, delegates to SignerLogic |
| `SignerLogic` | Core signing logic. Takes `BasicConfig` + `File inFile, File outFile` |
| `config/BasicConfig` | JCommander config - pure data holder, no logic |
| `config/TsaConfig` | TSA parameters (delegate of BasicConfig) |
| `config/TrustConfig` | Trust parameters (delegate of BasicConfig) |
| `config/Pkcs11Config` | PKCS#11 parameters (separate JCommander object) |
| `config/PadesLevel` | Enum mapping to DSS SignatureLevel |
| `KeyStoreUtils` | Keystore loading and key alias listing |
| `Pkcs11Initializer` | PKCS#11 provider registration (Closeable) |
| `TrustedCertSourcesProvider` | Builds DSS trust sources from TrustConfig |
| `types/*` | Enums: CertificationLevel, PrintRight, ServerAuthentication |
| `utils/PrivateKeySignatureToken` | DSS adapter wrapping PrivateKey + cert chain |
| `utils/FontUtils` | Loads DejaVuSans font for visible signatures |

### Validator Module

| Class | Role |
|-------|------|
| `Main` | CLI entry point with exit codes (0/1/2) |
| `SignatureValidator` | Core validation using DSS SignedDocumentValidator |
| `ValidationResult` | Wraps DSS Reports (SimpleReport, DetailedReport, DiagnosticData) |
| `ValidationOutput` | Formats results as TEXT, XML, ETSI, or JSON |
| `config/ValidatorConfig` | JCommander config |
| `config/TrustConfig` | Trust parameters (independent copy) |
| `config/OutputFormat` | TEXT, XML, ETSI, JSON enum |

## Design Principles

- **Config classes are pure data holders** - no logic, no derived state, no mutable runtime fields. Defaults and conversions happen in the consumer (Main, SignerLogic).
- **SignerLogic.signFile(File, File)** takes input/output files as parameters, not from config. Config is immutable after parsing.
- **Modules are independent** - validator doesn't import signer classes. Shared patterns (TrustConfig) are duplicated for now. (They might be moved to a shared common module in the future.)
- **DSS library does the heavy lifting** - signing, validation, certificate verification, TSA, OCSP/CRL are all delegated to DSS.

## Testing

- Tests use JUnit 5 with `@TempDir` for file isolation
- `SigningTestBase` is the abstract base for signing integration tests
- `TestConstants` defines test keystores and key aliases
- `EmbeddedTsaServer` provides an in-process RFC 3161 TSA for timestamp tests
- `PdfSignatureValidator` validates signatures independently using PDFBox + BouncyCastle
- Test keystores: `src/test/resources/test-keystore.jks` and `.p12` (password: `keystorepass`, keys: rsa1024/2048/4096, dsa1024, expired)
- Key password pattern: `<ALIAS>pass` (e.g., `RSA2048pass`)

## Dependencies

All dependency versions are managed in the parent POM via DSS BOM (`dss-bom` 6.2).

| Library | Purpose |
|---------|---------|
| `dss-pades-pdfbox` | PAdES signing with PDFBox |
| `dss-validation` | Signature validation and reports |
| `dss-service` | Online TSP, OCSP, CRL sources |
| `dss-token` | Signature token connections |
| `dss-tsl-validation` | Trusted Lists |
| BouncyCastle (`bcprov-jdk18on`, `bcpkix-jdk18on`) | Cryptography |
| Apache PDFBox 3.x | PDF manipulation |
| JCommander | CLI argument parsing |

## Common Tasks

### Adding a new CLI option
1. Add field with `@Parameter` annotation to `BasicConfig` (or the appropriate delegate config)
2. Add getter/setter
3. Use the field in `SignerLogic` or `Main`
4. Add tests

### Adding a new signing feature
1. Add config fields to `BasicConfig`
2. Implement in `SignerLogic.signFile()` or a private method called from it
3. Add tests extending `SigningTestBase`

### Adding a new validation output format
1. Add value to `OutputFormat` enum
2. Add formatting method in `ValidationOutput`
3. Add test in `ValidationOutputTest`
