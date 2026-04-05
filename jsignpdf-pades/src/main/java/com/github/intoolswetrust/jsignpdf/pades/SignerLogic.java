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
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.PadesLevel;
import com.github.intoolswetrust.jsignpdf.pades.config.TsaConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.VisibleSignatureConfig;
import com.github.intoolswetrust.jsignpdf.pades.types.CertificationLevel;
import com.github.intoolswetrust.jsignpdf.pades.types.PrintRight;
import com.github.intoolswetrust.jsignpdf.pades.types.ServerAuthentication;
import com.github.intoolswetrust.jsignpdf.pades.utils.FontUtils;
import com.github.intoolswetrust.jsignpdf.pades.utils.PrivateKeySignatureToken;

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
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

/**
 * Main logic of signer application. It uses DSS PAdES for creating signatures in PDF.
 */
public class SignerLogic {

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

                CommonCertificateVerifier verifier = new CommonCertificateVerifier();
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
                        tsDataLoader.addAuthentication(tsaUri.getHost(), tsaUri.getPort(), null, tsaUser,
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
                        parameters.getSignatureTimestampParameters()
                                .setDigestAlgorithm(DigestAlgorithm.forJavaName(tsaHashAlg));
                    }
                    service.setTspSource(tspSource);
                }

                LOGGER.info("Processing signature.");
                LOGGER.info("Creating signature.");
                ToBeSigned dataToSign = service.getDataToSign(document, parameters);
                SignatureValue signatureValue = token.sign(dataToSign, digestAlgorithm, null);
                DSSDocument signedDocument = service.signDocument(document, parameters, signatureValue);

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

    private AccessPermission buildAccessPermission() {
        AccessPermission ap = new AccessPermission();
        PrintRight printing = options.getRightPrinting();
        if (printing == null) {
            printing = PrintRight.ALLOW_PRINTING;
        }
        ap.setCanPrint(printing == PrintRight.ALLOW_PRINTING);
        ap.setCanPrintFaithful(printing != PrintRight.DISALLOW_PRINTING);
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
                signatureText = StrSubstitutor.replace(visConfig.getText(), replacements);
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
