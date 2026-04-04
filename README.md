# jsignpdf-pades

A Java CLI application and library for signing and validating PDF files using PAdES (PDF Advanced Electronic Signatures). Built on the EU Digital Signature Service (DSS) library and Apache PDFBox.

## Features

- PAdES signature levels: Baseline-B, Baseline-T, Baseline-LT, Baseline-LTA
- Keystore support: PKCS#12, JKS, PKCS#11 (smart cards/HSM)
- Visible signatures with text, images, placeholders, and positioning
- Image-only signature mode
- Blank page insertion for signature placement
- PDF encryption (encrypt-before-sign) with permission controls
- Password-protected PDF signing
- DocMDP certification levels (4 levels)
- Multiple/counter-signatures (append mode)
- Timestamp Authority (TSA) with Basic Auth, Mutual TLS, policy OID, and hash algorithm options
- Trust configuration: EU LOTL, custom certificates, truststores
- OCSP and CRL revocation checking with AIA chain building
- Hash algorithms: SHA-1, SHA-256, SHA-384, SHA-512, RIPEMD-160
- Signature validation with ETSI reports (TEXT, XML, ETSI TS 119 102-2, JSON)

## Modules

| Module | Artifact | Description |
|--------|----------|-------------|
| `jsignpdf-pades` | `jsignpdf-pades` | PDF signing CLI and library |
| `validator` | `jsignpdf-pades-validator` | PDF signature validation CLI and library |
| `distribution` | `jsignpdf-pades-distribution` | Distribution assembly (ZIP) |

## Requirements

- Java 11 or later
- Maven 3.6+ (for building)

## Building

```bash
mvn clean package
```

The fat JARs (with all dependencies) are created in each module's `target/` directory.

## Usage

### Signing

```bash
# Basic signing
java -jar jsignpdf-pades.jar -kst PKCS12 -ksf keystore.p12 -ksp password -ka mykey document.pdf

# Sign with timestamp
java -jar jsignpdf-pades.jar -kst PKCS12 -ksf keystore.p12 -ksp password \
  -ts http://tsa.example.com document.pdf

# Visible signature with text
java -jar jsignpdf-pades.jar -kst PKCS12 -ksf keystore.p12 -ksp password \
  -V -pg 1 -llx 50 -lly 50 -urx 250 -ury 120 \
  -r "Approved" -l "Prague" document.pdf

# Image-only visible signature
java -jar jsignpdf-pades.jar -kst PKCS12 -ksf keystore.p12 -ksp password \
  -V --image-only --bg-path logo.png -llx 50 -lly 50 -urx 200 -ury 100 document.pdf

# Add blank page for signature
java -jar jsignpdf-pades.jar -kst PKCS12 -ksf keystore.p12 -ksp password \
  -V --add-blank-page -llx 100 -lly 300 -urx 400 -ury 500 document.pdf

# Encrypt and sign
java -jar jsignpdf-pades.jar -kst PKCS12 -ksf keystore.p12 -ksp password \
  --encrypt-before-sign -opwd owner123 -upwd user123 document.pdf
```

### Validation

```bash
# Validate with text output
java -jar jsignpdf-pades-validator.jar signed.pdf

# JSON output for scripting
java -jar jsignpdf-pades-validator.jar -f JSON signed.pdf

# ETSI TS 119 102-2 XML report
java -jar jsignpdf-pades-validator.jar -f ETSI signed.pdf

# Quiet mode (exit code only, for CI/CD)
java -jar jsignpdf-pades-validator.jar -q signed.pdf && echo "VALID" || echo "INVALID"

# With EU trusted list
java -jar jsignpdf-pades-validator.jar --trust-use-default-lotl signed.pdf

# Skip online revocation checks
java -jar jsignpdf-pades-validator.jar --skip-revocation signed.pdf
```

### Other Commands

```bash
# List available keystore types
java -jar jsignpdf-pades.jar -lkt

# List keys in a keystore
java -jar jsignpdf-pades.jar -lk -kst PKCS12 -ksf keystore.p12 -ksp password

# Print help
java -jar jsignpdf-pades.jar -h
java -jar jsignpdf-pades-validator.jar -h
```

## Signing CLI Options

### Keystore
| Option | Description |
|--------|-------------|
| `-kst, --keystore-type` | Keystore type (JKS, PKCS12, etc.) |
| `-ksf, --keystore-file` | Path to keystore file |
| `-ksp, --keystore-password` | Keystore password |
| `-kp, --key-password` | Key password (if different from keystore password) |
| `-ka, --key-alias` | Key alias to use for signing |

### Signature
| Option | Description |
|--------|-------------|
| `-pl, --pades-level` | PAdES level: BASELINE_B, BASELINE_T, BASELINE_LT, BASELINE_LTA |
| `-da, --digest-algorithm` | Digest algorithm: SHA1, SHA256, SHA384, SHA512, RIPEMD160 |
| `-cl, --certification-level` | Certification level: NOT_CERTIFIED, CERTIFIED_NO_CHANGES_ALLOWED, CERTIFIED_FORM_FILLING, CERTIFIED_FORM_FILLING_AND_ANNOTATIONS |
| `-r, --reason` | Reason for signature |
| `-l, --location` | Location of signature |
| `-c, --contact` | Contact info |
| `-sn, --signer-name` | Signer name override |

### Visible Signature
| Option | Description |
|--------|-------------|
| `-V, --visible-signature` | Enable visible signature |
| `-pg, --page` | Page number (default: 1) |
| `-llx, -lly, -urx, -ury` | Signature rectangle coordinates |
| `-t, --text` | Custom text with placeholders: `${signer}`, `${reason}`, `${location}`, `${contact}`, `${timestamp}`, `${certificate}` |
| `-ff, --font-file` | TTF font file for visible signature text |
| `-fs, --font-size` | Font size (default: 10) |
| `--bg-path` | Background/logo image path |
| `--image-only` | Image-only mode (no text) |
| `--add-blank-page` | Add blank page for signature |

### TSA (Timestamp Authority)
| Option | Description |
|--------|-------------|
| `-ts, --tsa-server-url` | TSA server URL |
| `-ta, --tsa-authentication` | TSA auth: NONE, PASSWORD, CERTIFICATE |
| `-tsu, --tsa-user` | TSA username |
| `-tsp, --tsa-password` | TSA password |
| `-tsh, --tsa-hash-algorithm` | TSA hash algorithm |
| `--tsa-policy-oid` | TSA policy OID |
| `-tskt, --tsa-key-file-type` | TSA client cert keystore type |
| `-tskf, --tsa-key-file` | TSA client cert keystore file |
| `-tskp, --tsa-key-password` | TSA client cert keystore password |

### Trust
| Option | Description |
|--------|-------------|
| `--trust-use-default-lotl` | Use EU List of Trusted Lists |
| `--trust-lotl-url` | Custom LOTL URL (repeatable) |
| `--trust-certificate-file` | Trusted certificate file (repeatable) |
| `--trust-certificate-url` | Trusted certificate URL (repeatable) |
| `--trust-keystore-file` | Truststore file |
| `--trust-keystore-password` | Truststore password |
| `--trust-keystore-type` | Truststore type |

### Encryption
| Option | Description |
|--------|-------------|
| `--encrypt-before-sign` | Encrypt PDF with password before signing |
| `-opwd, --owner-password` | Owner password |
| `-upwd, --user-password` | User password |
| `-pr, --print-right` | Print right: DISALLOW_PRINTING, ALLOW_DEGRADED_PRINTING, ALLOW_PRINTING |
| `--disable-copy` | Deny content copying |
| `--disable-assembly` | Deny document assembly |
| `--disable-fill` | Deny form filling |
| `--disable-screen-readers` | Deny screen reader access |
| `--disable-modify-annotations` | Deny annotation modification |
| `--disable-modify-content` | Deny content modification |

### Output
| Option | Description |
|--------|-------------|
| `-os, --out-suffix` | Output file suffix (default: `_signed`) |
| `-d, --out-directory` | Output directory |
| `-q, --quiet` | Quiet mode |

## Validation CLI Options

| Option | Description |
|--------|-------------|
| `-f, --format` | Output format: TEXT, XML, ETSI, JSON |
| `--verbose` | Include detailed report |
| `-q, --quiet` | Only exit code (0=valid, 1=invalid, 2=error) |
| `--skip-revocation` | Skip online OCSP/CRL checks |
| Trust options | Same as signing (see above) |


## Related Projects

- [jsignpdf](https://github.com/intoolswetrust/jsignpdf) - GUI+CLI PDF signing with OpenPDF
- [jsign-pkcs11](https://github.com/intoolswetrust/jsign-pkcs11) - SunPKCS11 fork with context-specific login support
