package com.github.intoolswetrust.jsignpdf.pades;

import static com.github.intoolswetrust.jsignpdf.pades.Constants.LOGGER;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.SIG_TEXT_PLACEHOLDER_CERTIFICATE;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.SIG_TEXT_PLACEHOLDER_CONTACT;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.SIG_TEXT_PLACEHOLDER_LOCATION;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.SIG_TEXT_PLACEHOLDER_REASON;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.SIG_TEXT_PLACEHOLDER_SIGNER;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.SIG_TEXT_PLACEHOLDER_TIMESTAMP;

import java.io.File;
import java.io.FileOutputStream;
import java.net.URI;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;

import com.github.intoolswetrust.jsignpdf.pades.common.TrustConfig;
import com.github.intoolswetrust.jsignpdf.pades.common.TrustedCertSourcesProvider;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.PadesLevel;
import com.github.intoolswetrust.jsignpdf.pades.config.TsaConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.VisibleSignatureConfig;
import com.github.intoolswetrust.jsignpdf.pades.types.CertificationLevel;
import com.github.intoolswetrust.jsignpdf.pades.types.PrintRight;
import com.github.intoolswetrust.jsignpdf.pades.types.ServerAuthentication;
import com.github.intoolswetrust.jsignpdf.pades.utils.FontUtils;
import com.github.intoolswetrust.jsignpdf.pades.utils.PrivateKeySignatureToken;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.DSSFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

/**
 * Main logic of signer application. It uses DSS PAdES for creating signatures in PDF.
 */
public class SignerLogic {

    /**
     * The digest algorithms PAdES permits. SHA-1, RIPEMD-160 and the like are rejected rather than silently
     * used: DSS would happily produce such a signature, but no strict PAdES validator accepts it.
     */
    private static final Set<DigestAlgorithm> PADES_DIGEST_ALGORITHMS = Collections.unmodifiableSet(EnumSet.of(
            DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
            DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512));

    /** Lower bound for the reserved {@code /Contents} size, matching DSS's own default; never estimate below it. */
    private static final int MIN_CONTENT_SIZE = 9472;

    /** Per-certificate fallback used only when a chain certificate cannot be DER-encoded for measurement. */
    private static final int CERT_SIZE_FALLBACK = 2048;

    /**
     * Headroom added on top of the certificate-chain bytes for the signer info, signed attributes, the
     * signature value (comfortably covers RSA-4096) and the ASN.1 framing of the CMS SignedData.
     */
    private static final int CMS_OVERHEAD = 4096;

    /**
     * Extra space reserved when a signature timestamp is embedded (PAdES level T and above). The timestamp
     * token carries its own TSA certificate chain and is by far the largest single variable in {@code /Contents}.
     */
    private static final int TSA_ALLOWANCE = 16384;

    /** Slack added on top of the exact size DSS reports when growing after an undersize failure. */
    private static final int RETRY_MARGIN = 2048;

    /** Cap on undersize retries; DSS reports the exact required size, so a single retry normally suffices. */
    private static final int MAX_CONTENT_SIZE_RETRIES = 3;

    /** Extracts the actual CMS length from the DSS "signature size too small" message. */
    private static final Pattern UNDERSIZE_LENGTH_PATTERN = Pattern.compile("with a length \\[(\\d+)\\]");

    private final BasicConfig options;

    public SignerLogic(final BasicConfig anOptions) {
        if (anOptions == null) {
            throw new NullPointerException("Options has to be filled.");
        }
        options = anOptions;
    }

    /**
     * Signs a single file.
     *
     * @param inFile input PDF file
     * @param outFile output PDF file
     * @return true when signing is finished successfully, false otherwise
     */
    public boolean signFile(File inFile, File outFile) {
        if (!validateInOutFiles(inFile, outFile)) {
            LOGGER.info("Skipping signing.");
            return false;
        }
        if (!PADES_DIGEST_ALGORITHMS.contains(options.getDigestAlgorithm())) {
            LOGGER.severe("Digest algorithm " + options.getDigestAlgorithm().getName()
                    + " is not allowed in PAdES signatures. Use one of: " + PADES_DIGEST_ALGORITHMS);
            LOGGER.info("Skipping signing.");
            return false;
        }

        final VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        boolean finished = false;
        File encryptedTempFile = null;
        File blankPageTempFile = null;
        try {
            final KeyStore ks = KeyStoreUtils.loadKeyStore(options.getKeyStoreType(), options.getKeyStoreFile(),
                    options.getKeyStorePassword());
            String alias = options.getKeyAlias();
            if (StringUtils.isEmpty(alias)) {
                java.util.Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    String a = aliases.nextElement();
                    if (ks.isKeyEntry(a)) {
                        alias = a;
                        break;
                    }
                }
            }

            char[] keyPasswd = options.getKeyPassword();
            if (keyPasswd == null || keyPasswd.length == 0) {
                keyPasswd = options.getKeyStorePassword();
            }
            PrivateKey key = (PrivateKey) ks.getKey(alias, keyPasswd);
            Certificate[] chain = ks.getCertificateChain(alias);

            if (ArrayUtils.isEmpty(chain)) {
                LOGGER.info("Certificate chain is empty.");
                return false;
            }

            try (PrivateKeySignatureToken token = new PrivateKeySignatureToken(key, chain)) {
                DSSPrivateKeyEntry keyEntry = token.getKeyEntry();

                PAdESSignatureParameters parameters = new PAdESSignatureParameters();

                DigestAlgorithm digestAlgorithm = options.getDigestAlgorithm();

                parameters.setDigestAlgorithm(digestAlgorithm);
                parameters.setSigningCertificate(keyEntry.getCertificate());
                parameters.setCertificateChain(keyEntry.getCertificateChain());

                TsaConfig tsaConfig = options.getTsaConfig();
                String tsaUrl = tsaConfig.getTsaServerUrl();
                boolean useTsa = StringUtils.isNotEmpty(tsaUrl);
                PadesLevel padesLevel = options.getPadesLevel();
                if (useTsa && padesLevel == PadesLevel.BASELINE_B) {
                    LOGGER.info("Timestamping is used, changing PadesLevel " + PadesLevel.BASELINE_B + "->"
                            + PadesLevel.BASELINE_T);
                    parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
                } else {
                    parameters.setSignatureLevel(padesLevel.getSignatureLevel());
                }

                Calendar signingCal = Calendar.getInstance();
                parameters.bLevel().setSigningDate(signingCal.getTime());

                // Metadata
                final String reason = options.getReason();
                if (StringUtils.isNotEmpty(reason)) {
                    LOGGER.info("Setting reason: " + reason);
                    parameters.setReason(reason);
                }
                final String location = options.getLocation();
                if (StringUtils.isNotEmpty(location)) {
                    LOGGER.info("Setting location: " + location);
                    parameters.setLocation(location);
                }
                final String contact = options.getContact();
                if (StringUtils.isNotEmpty(contact)) {
                    LOGGER.info("Setting contact: " + contact);
                    parameters.setContactInfo(contact);
                }

                // Certification level
                LOGGER.info("Setting certification level.");
                CertificationLevel certLevel = options.getCertLevel();
                if (certLevel != null) {
                    CertificationPermission permission = certLevel.toDssCertificationPermission();
                    if (permission != null) {
                        parameters.setPermission(permission);
                    }
                }

                // Password for encrypted PDFs
                char[] ownerPwd = options.getPdfOwnerPwd();
                if (ownerPwd != null && ownerPwd.length > 0) {
                    parameters.setPasswordProtection(ownerPwd);
                }

                // Encrypt PDF if requested (encrypt-before-sign)
                if (options.isEncryptBeforeSign()) {
                    LOGGER.info("Setting encryption.");
                    encryptedTempFile = encryptPdf(inFile);
                    if (encryptedTempFile == null) {
                        return false;
                    }
                    // DSS must open the temp with the password encryptPdf just used. PDFBox treats an empty
                    // owner password as "owner = user password", so when no owner password was given the temp
                    // is encrypted under the user password and that is the only one that opens it.
                    char[] openPwd = ownerPwd != null && ownerPwd.length > 0 ? ownerPwd : options.getPdfUserPwd();
                    if (openPwd != null && openPwd.length > 0) {
                        parameters.setPasswordProtection(openPwd);
                    }
                }

                // Add blank page if requested (before loading as DSSDocument)
                File effectiveInFile = encryptedTempFile != null ? encryptedTempFile : inFile;
                if (visConfig.isVisible() && visConfig.isAddBlankPage()) {
                    blankPageTempFile = addBlankPage(effectiveInFile);
                    if (blankPageTempFile == null) {
                        return false;
                    }
                    effectiveInFile = blankPageTempFile;
                }

                // Load input document
                DSSDocument document = new FileDocument(effectiveInFile);

                // Handle visible signature
                if (visConfig.isVisible()) {
                    LOGGER.info("Configuring visible signature.");
                    configureVisibleSignature(parameters, chain, signingCal, effectiveInFile);
                }

                // LT/LTA embed validation material, which DSS collects only for a chain it can anchor and only
                // when it may go online. Both conditions are config, so check them here instead of failing deep
                // inside signDocument() after the PDF, the key and a TSA round-trip have already been spent.
                boolean ltOrLta = padesLevel == PadesLevel.BASELINE_LT || padesLevel == PadesLevel.BASELINE_LTA;
                if (ltOrLta && !checkLtPreconditions(useTsa)) {
                    return false;
                }

                final CommonCertificateVerifier verifier;
                try {
                    verifier = buildCertificateVerifier();
                } catch (Exception e) {
                    // A configured trust source could not be loaded (bad truststore path or password, unreadable
                    // certificate file, unreachable LOTL). Fail rather than sign with trust material that is not
                    // what was asked for, and surface an opaque DSS error later.
                    LOGGER.log(Level.SEVERE, "Failed to configure the trust sources.", e);
                    return false;
                }
                PAdESService service = new PAdESService(verifier);

                // Configure TSA
                if (useTsa) {
                    LOGGER.info("Creating TSA client.");
                    TimestampDataLoader tsDataLoader = new TimestampDataLoader();
                    if (options.isInsecureRelaxTls()) {
                        tsDataLoader.setTrustStrategy((certChain, type) -> true);
                    }
                    if (tsaConfig.getTsaServerAuthn() == ServerAuthentication.PASSWORD) {
                        URI tsaUri = URI.create(tsaUrl);
                        String tsaUser = tsaConfig.getTsaUser();
                        char[] tsaPassword = tsaConfig.getTsaPassword();
                        tsDataLoader.addAuthentication(tsaUri.getHost(), resolvePort(tsaUri), null, tsaUser,
                                tsaPassword);
                    }
                    OnlineTSPSource tspSource = new OnlineTSPSource(tsaUrl, tsDataLoader);

                    final String policyOid = tsaConfig.getTsaPolicyOid();
                    if (StringUtils.isNotEmpty(policyOid)) {
                        LOGGER.info("Setting TSA policy: " + policyOid);
                        tspSource.setPolicyOid(policyOid);
                    }
                    String tsaHashAlg = tsaConfig.getTsaHashAlgorithm();
                    if (StringUtils.isNotEmpty(tsaHashAlg)) {
                        LOGGER.info("Setting TSA hash algorithm: " + tsaHashAlg);
                        // All three timestamp kinds, or the archive timestamp an LTA signature adds would keep
                        // the DSS default and the requested algorithm would only be half applied.
                        DigestAlgorithm tsaDigest = DigestAlgorithm.forJavaName(tsaHashAlg);
                        parameters.getContentTimestampParameters().setDigestAlgorithm(tsaDigest);
                        parameters.getSignatureTimestampParameters().setDigestAlgorithm(tsaDigest);
                        parameters.getArchiveTimestampParameters().setDigestAlgorithm(tsaDigest);
                    }
                    service.setTspSource(tspSource);
                }

                LOGGER.info("Processing signature.");
                LOGGER.info("Creating signature.");
                int configuredContentSize = options.getContentSize();
                int initialContentSize = configuredContentSize > 0 ? configuredContentSize
                        : estimateContentSize(chain, useTsa);
                DSSDocument signedDocument = signWithContentSize(service, document, parameters, token,
                        digestAlgorithm, initialContentSize, options.isRetryOnUndersize());

                LOGGER.info("Creating output PDF: " + outFile);
                try (FileOutputStream fos = new FileOutputStream(outFile)) {
                    signedDocument.writeTo(fos);
                }
                LOGGER.info("Output stream closed.");
            }
            finished = true;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Exception during signing.", e);
        } finally {
            if (encryptedTempFile != null) {
                encryptedTempFile.delete();
            }
            if (blankPageTempFile != null) {
                blankPageTempFile.delete();
            }
            LOGGER.info("Signing " + (finished ? "finished successfully." : "failed."));
        }
        return finished;
    }

    /**
     * Checks the configuration an LT/LTA signature needs before any expensive work is done. Each of these
     * otherwise fails deep inside DSS with an opaque alert about missing revocation data.
     *
     * @param useTsa whether a timestamp server is configured
     * @return {@code true} when LT/LTA can be attempted
     */
    private boolean checkLtPreconditions(boolean useTsa) {
        TrustConfig trustConfig = options.getTrustConfig();
        if (!useTsa) {
            // LT/LTA build on a signature timestamp (level T).
            LOGGER.severe("PAdES level " + options.getPadesLevel() + " requires a timestamp."
                    + " Set a timestamp server with --tsa-server-url.");
            return false;
        }
        if (!options.isOnline()) {
            LOGGER.severe("PAdES level " + options.getPadesLevel() + " embeds revocation data, which cannot be"
                    + " fetched in offline mode. Drop --offline.");
            return false;
        }
        if (!trustConfig.hasTrustSource() && !options.isAllowUntrusted()) {
            // DSS skips revocation fetching entirely for a chain it cannot anchor, so without a trust source the
            // level is unreachable no matter what the CA publishes.
            LOGGER.severe("PAdES level " + options.getPadesLevel() + " needs a trust anchor for the signing"
                    + " certificate, but no trust source is configured. Use --trust-use-default-lotl,"
                    + " --trust-certificate-file, --trust-keystore-file or --trust-system-store"
                    + " (or --trust-allow-untrusted for a private PKI).");
            return false;
        }
        return true;
    }

    /**
     * Builds the verifier DSS resolves trust anchors and revocation data through. Levels B and T need neither,
     * but the sources are configured regardless: they are what the user asked for, and DSS consults them only
     * for the levels that embed validation material.
     */
    private CommonCertificateVerifier buildCertificateVerifier() throws Exception {
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();

        CertificateSource[] trustedSources =
                new TrustedCertSourcesProvider(options.getTrustConfig()).createTrustedCertSources();
        if (trustedSources.length > 0) {
            verifier.setTrustedCertSources(trustedSources);
        }

        if (options.isOnline()) {
            OCSPDataLoader ocspDataLoader = new OCSPDataLoader();
            CommonsDataLoader dataLoader = new CommonsDataLoader();
            if (options.isInsecureRelaxTls()) {
                ocspDataLoader.setTrustStrategy((certChain, type) -> true);
                dataLoader.setTrustStrategy((certChain, type) -> true);
            }
            verifier.setAIASource(new DefaultAIASource(dataLoader));
            verifier.setOcspSource(new OnlineOCSPSource(ocspDataLoader));
            verifier.setCrlSource(new OnlineCRLSource(dataLoader));
        }

        if (options.isAllowUntrusted()) {
            relaxTrustAndRevocationAlerts(verifier);
        }
        return verifier;
    }

    /**
     * Downgrades the alerts that otherwise abort LT/LTA when the signer chain is self-signed or carries no
     * revocation data: each becomes a warning, so DSS attaches the baseline structure it can and logs what is
     * missing. The result is not a conformant long-term signature — see {@code --trust-allow-untrusted}.
     */
    private static void relaxTrustAndRevocationAlerts(CommonCertificateVerifier verifier) {
        LOGGER.warning("Trusting an untrusted certificate chain (--trust-allow-untrusted). The signature will"
                + " have the LT/LTA structure but not the revocation data the level requires, so strict"
                + " validators will not accept it as LT/LTA.");
        LogOnStatusAlert warn = new LogOnStatusAlert(org.slf4j.event.Level.WARN);
        verifier.setAugmentationAlertOnSelfSignedCertificateChains(warn);
        verifier.setAugmentationAlertOnSignatureWithoutCertificates(warn);
        verifier.setAlertOnMissingRevocationData(warn);
        verifier.setAlertOnUncoveredPOE(warn);
        verifier.setAlertOnNoRevocationAfterBestSignatureTime(warn);
    }

    /**
     * Estimates how many bytes to reserve in the PDF {@code /Contents} for the CMS signature. DSS uses a fixed
     * reservation ({@value #MIN_CONTENT_SIZE} bytes) that is too small for large certificate chains (eID /
     * qualified certificates) combined with an embedded signature timestamp. Sizing from the actual chain plus a
     * fixed timestamp allowance covers those in a single pass; {@link #signWithContentSize} is the safety net
     * when even this is too small.
     *
     * <p>
     * The estimate cannot be exact for timestamped signatures: the TSA token (with its own certificate chain) is
     * only known once the TSA responds inside {@code signDocument()}, so a fixed {@link #TSA_ALLOWANCE} is
     * reserved instead.
     * </p>
     *
     * @param chain         the signer's certificate chain (all of it is encapsulated in the CMS)
     * @param withTimestamp whether a signature timestamp will be embedded (PAdES level T and above)
     * @return the number of bytes to reserve, never below {@link #MIN_CONTENT_SIZE}
     */
    private static int estimateContentSize(Certificate[] chain, boolean withTimestamp) {
        int chainBytes = 0;
        for (Certificate cert : chain) {
            try {
                chainBytes += cert.getEncoded().length;
            } catch (CertificateEncodingException e) {
                chainBytes += CERT_SIZE_FALLBACK;
            }
        }
        int estimate = chainBytes + CMS_OVERHEAD;
        if (withTimestamp) {
            estimate += TSA_ALLOWANCE;
        }
        return Math.max(estimate, MIN_CONTENT_SIZE);
    }

    /**
     * Signs the document, reserving {@code initialContentSize} bytes for the CMS {@code /Contents}. The reserved
     * size is fixed before the byte ranges are digested, so it cannot be derived from the produced signature;
     * when {@code retryOnUndersize} is enabled and DSS reports the reservation was too small, this re-runs the
     * whole signing operation with the exact size DSS reported (plus {@link #RETRY_MARGIN}). For timestamped
     * levels each retry fetches a fresh TSA token, hence the {@link #MAX_CONTENT_SIZE_RETRIES} cap.
     */
    private DSSDocument signWithContentSize(PAdESService service, DSSDocument document,
            PAdESSignatureParameters parameters, PrivateKeySignatureToken token, DigestAlgorithm digestAlgorithm,
            int initialContentSize, boolean retryOnUndersize) {
        int contentSize = initialContentSize;
        for (int attempt = 0;; attempt++) {
            parameters.setContentSize(contentSize);
            if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.fine("Signing attempt " + attempt + " reserving " + contentSize + " bytes for /Contents");
            }
            ToBeSigned dataToSign = service.getDataToSign(document, parameters);
            SignatureValue signatureValue = token.sign(dataToSign, digestAlgorithm, null);
            try {
                return service.signDocument(document, parameters, signatureValue);
            } catch (IllegalArgumentException e) {
                Integer required = parseRequiredContentSize(e.getMessage());
                // Doubling is the fallback when the required size cannot be parsed; the guard below stops a
                // non-growing loop in that case.
                int grown = required != null ? required + RETRY_MARGIN : contentSize * 2;
                if (!retryOnUndersize || attempt >= MAX_CONTENT_SIZE_RETRIES || grown <= contentSize) {
                    logUndersizeGuidance(contentSize, required, retryOnUndersize);
                    throw e;
                }
                LOGGER.info("Reserved " + contentSize + " bytes for the signature, which was too small."
                        + " Retrying with " + grown + " bytes.");
                contentSize = grown;
            }
        }
    }

    /**
     * Logs an actionable message when an undersized {@code /Contents} cannot be recovered, pointing at the two
     * options that control it. Without this the only feedback is the raw DSS {@link IllegalArgumentException},
     * which names a DSS API call rather than anything the user can set.
     *
     * @param contentSize the reservation that proved too small
     * @param required    the size DSS reported as needed, or {@code null} if it could not be parsed
     */
    private static void logUndersizeGuidance(int contentSize, Integer required, boolean retryOnUndersize) {
        int suggested = (required != null ? required : contentSize * 2) + RETRY_MARGIN;
        if (retryOnUndersize) {
            // Retry was enabled but exhausted / not progressing: only the explicit override is left.
            LOGGER.severe("Could not reserve enough space for the signature (last attempt: " + contentSize
                    + " bytes). Set --content-size " + suggested + " to reserve it explicitly.");
        } else {
            LOGGER.severe("Reserved " + contentSize + " bytes for the signature, which is too small, and"
                    + " --no-retry-on-undersize is set. Set --content-size " + suggested + " or drop the flag.");
        }
    }

    /**
     * Parses the required CMS length out of the DSS "signature size is too small" message, so the retry can
     * reserve exactly that (plus a margin). Returns {@code null} when the message does not match, in which case
     * the caller falls back to doubling.
     */
    private static Integer parseRequiredContentSize(String message) {
        if (message == null) {
            return null;
        }
        Matcher matcher = UNDERSIZE_LENGTH_PATTERN.matcher(message);
        if (matcher.find()) {
            try {
                return Integer.valueOf(matcher.group(1));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /** Resolves the port for TSA basic-auth registration, defaulting from the scheme when the URL omits it. */
    static int resolvePort(URI uri) {
        int port = uri.getPort();
        if (port >= 0) {
            return port;
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private AccessPermission buildAccessPermission() {
        AccessPermission ap = new AccessPermission();
        PrintRight printing = options.getRightPrinting();
        if (printing == null) {
            printing = PrintRight.ALLOW_PRINTING;
        }
        ap.setCanPrint(printing != PrintRight.DISALLOW_PRINTING);
        ap.setCanPrintFaithful(printing == PrintRight.ALLOW_PRINTING);
        ap.setCanExtractContent(!options.isDisableCopy());
        ap.setCanAssembleDocument(!options.isDisableAssembly());
        ap.setCanFillInForm(!options.isDisableFill());
        ap.setCanExtractForAccessibility(!options.isDisableScreenReaders());
        ap.setCanModifyAnnotations(!options.isDisableModifyAnnotations());
        ap.setCanModify(!options.isDisableModifyContent());
        return ap;
    }

    private File encryptPdf(File inFile) throws Exception {
        try (PDDocument doc = Loader.loadPDF(inFile)) {
            if (!doc.getSignatureDictionaries().isEmpty()) {
                LOGGER.info("Cannot encrypt PDF with existing signatures.");
                return null;
            }

            AccessPermission ap = buildAccessPermission();
            String encOwnerPwd = options.getPdfOwnerPwd() != null ? new String(options.getPdfOwnerPwd()) : "";
            String encUserPwd = options.getPdfUserPwd() != null ? new String(options.getPdfUserPwd()) : "";
            StandardProtectionPolicy passwordPolicy = new StandardProtectionPolicy(encOwnerPwd, encUserPwd, ap);
            passwordPolicy.setEncryptionKeyLength(128);
            doc.protect(passwordPolicy);

            File tempFile = File.createTempFile("jsignpdf-enc-", ".pdf");
            tempFile.deleteOnExit();
            doc.save(tempFile);
            return tempFile;
        }
    }

    private File addBlankPage(File inputFile) throws Exception {
        try (PDDocument doc = Loader.loadPDF(inputFile)) {
            if (!doc.getSignatureDictionaries().isEmpty()) {
                LOGGER.info("Cannot add blank page to a PDF with existing signatures (would invalidate them).");
                return null;
            }
            File tempFile = File.createTempFile("jsignpdf-blank-", ".pdf");
            tempFile.deleteOnExit();
            doc.addPage(new PDPage());
            doc.save(tempFile);
            return tempFile;
        }
    }

    private void configureVisibleSignature(PAdESSignatureParameters parameters, Certificate[] chain, Calendar signingCal,
            File inFile) throws Exception {
        final VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        SignatureImageParameters imageParams = new SignatureImageParameters();

        int page = visConfig.getPage();
        float pageWidth;
        float pageHeight;
        try (PDDocument pdDoc = Loader.loadPDF(inFile)) {
            int totalPages = pdDoc.getNumberOfPages();
            if (visConfig.isAddBlankPage()) {
                // Blank page was added as last page — use it
                page = totalPages;
            } else if (page < 1 || page > totalPages) {
                page = totalPages;
            }
            PDPage pdPage = pdDoc.getPage(page - 1);
            PDRectangle mediaBox = pdPage.getMediaBox();
            int rotation = pdPage.getRotation();
            if (rotation == 90 || rotation == 270) {
                pageWidth = mediaBox.getHeight();
                pageHeight = mediaBox.getWidth();
            } else {
                pageWidth = mediaBox.getWidth();
                pageHeight = mediaBox.getHeight();
            }
        }

        float llx = fixPosition(visConfig.getPositionLLX(), pageWidth);
        float lly = fixPosition(visConfig.getPositionLLY(), pageHeight);
        float urx = fixPosition(visConfig.getPositionURX(), pageWidth);
        float ury = fixPosition(visConfig.getPositionURY(), pageHeight);
        float width = urx - llx;
        float height = ury - lly;

        SignatureFieldParameters fieldParams = new SignatureFieldParameters();
        fieldParams.setPage(page);
        fieldParams.setOriginX(llx);
        fieldParams.setOriginY(pageHeight - ury);
        fieldParams.setWidth(width);
        fieldParams.setHeight(height);
        imageParams.setFieldParameters(fieldParams);

        // Set image if provided
        final String bgImgPath = visConfig.getBgImgPath();
        if (bgImgPath != null) {
            LOGGER.info("Setting image: " + bgImgPath);
            imageParams.setImage(new FileDocument(bgImgPath));
        }

        // Image-only mode: skip text parameters
        if (!visConfig.isImageOnly()) {
            LOGGER.info("Setting signature text.");
            X509Certificate signerCert = (X509Certificate) chain[0];
            String signer = extractCN(signerCert);
            if (StringUtils.isNotEmpty(options.getSignerName())) {
                signer = options.getSignerName();
            }
            final String certificate = signerCert.getSubjectX500Principal().toString();
            final String timestamp = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss z").format(signingCal.getTime());

            String signatureText;
            if (visConfig.getText() != null) {
                final Map<String, String> replacements = new HashMap<>();
                replacements.put(SIG_TEXT_PLACEHOLDER_SIGNER, StringUtils.defaultString(signer));
                replacements.put(SIG_TEXT_PLACEHOLDER_CERTIFICATE, certificate);
                replacements.put(SIG_TEXT_PLACEHOLDER_TIMESTAMP, timestamp);
                replacements.put(SIG_TEXT_PLACEHOLDER_LOCATION, StringUtils.defaultString(options.getLocation()));
                replacements.put(SIG_TEXT_PLACEHOLDER_REASON, StringUtils.defaultString(options.getReason()));
                replacements.put(SIG_TEXT_PLACEHOLDER_CONTACT, StringUtils.defaultString(options.getContact()));
                signatureText = visConfig.getText();
                for (Map.Entry<String, String> e : replacements.entrySet()) {
                    signatureText = signatureText.replace("${" + e.getKey() + "}", e.getValue());
                }
            } else {
                final StringBuilder buf = new StringBuilder();
                buf.append("Signed by: ").append(signer).append('\n');
                buf.append("Date: ").append(timestamp);
                if (StringUtils.isNotEmpty(options.getReason()))
                    buf.append('\n').append("Reason: ").append(options.getReason());
                if (StringUtils.isNotEmpty(options.getLocation()))
                    buf.append('\n').append("Location: ").append(options.getLocation());
                signatureText = buf.toString();
            }

            SignatureImageTextParameters textParams = new SignatureImageTextParameters();
            textParams.setText(signatureText);

            DSSFont font = FontUtils.getVisibleSignatureFont(visConfig.getFontFile());
            if (font != null) {
                float fontSize = visConfig.getTextFontSize();
                if (fontSize <= 0f) {
                    fontSize = 10.0f;
                }
                font.setSize(fontSize);
                textParams.setFont(font);
            }
            imageParams.setTextParameters(textParams);
        }

        LOGGER.info("Setting visible signature parameters.");
        parameters.setImageParameters(imageParams);
    }

    private String extractCN(X509Certificate cert) {
        try {
            String dn = cert.getSubjectX500Principal().getName();
            LdapName ldapName = new LdapName(dn);
            for (Rdn rdn : ldapName.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
        } catch (Exception e) {
            // fall through
        }
        return cert.getSubjectX500Principal().toString();
    }

    private float fixPosition(float origPos, float base) {
        return origPos >= 0 ? origPos : base + origPos;
    }

    private boolean validateInOutFiles(File inFile, File outFile) {
        LOGGER.info("Validating input/output files.");
        if (inFile == null || outFile == null) {
            LOGGER.info("Input or output file is not specified.");
            return false;
        }
        if (!(inFile.exists() && inFile.isFile() && inFile.canRead())) {
            LOGGER.info("Input file not found or not readable: " + inFile);
            return false;
        }
        if (inFile.getAbsolutePath().equals(outFile.getAbsolutePath())) {
            LOGGER.info("Input and output files are the same.");
            return false;
        }
        return true;
    }

}
