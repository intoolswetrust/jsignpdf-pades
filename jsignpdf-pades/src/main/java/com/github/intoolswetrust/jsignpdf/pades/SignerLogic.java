package com.github.intoolswetrust.jsignpdf.pades;

import static com.github.intoolswetrust.jsignpdf.pades.Constants.L2TEXT_PLACEHOLDER_CERTIFICATE;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.L2TEXT_PLACEHOLDER_CONTACT;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.L2TEXT_PLACEHOLDER_LOCATION;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.L2TEXT_PLACEHOLDER_REASON;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.L2TEXT_PLACEHOLDER_SIGNER;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.L2TEXT_PLACEHOLDER_TIMESTAMP;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.LOGGER;

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
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.types.CertificationLevel;
import com.github.intoolswetrust.jsignpdf.pades.types.HashAlgorithm;
import com.github.intoolswetrust.jsignpdf.pades.types.PDFEncryption;
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
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

/**
 * Main logic of signer application. It uses DSS PAdES for creating signatures in PDF.
 *
 * @author Josef Cacek
 */
public class SignerLogic implements Runnable {

    private final BasicConfig options;

    public SignerLogic(final BasicConfig anOptions) {
        if (anOptions == null) {
            throw new NullPointerException("Options has to be filled.");
        }
        options = anOptions;
    }

    @Override
    public void run() {
        signFile();
    }

    /**
     * Signs a single file.
     *
     * @return true when signing is finished successfully, false otherwise
     */
    public boolean signFile() {
        final String outFile = options.getEffectiveOutFile();
        if (!validateInOutFiles(options.getInFile(), outFile)) {
            LOGGER.info("Skipping signing.");
            return false;
        }

        boolean finished = false;
        File encryptedTempFile = null;
        try {
            final KeyStore ks = KeyStoreUtils.loadKeyStore(
                    options.getKsType(),
                    options.getKeyStoreFile(),
                    options.getKeyStorePassword());

            String alias = options.getKeyAlias();
            if (StringUtils.isEmpty(alias)) {
                // use first key alias
                java.util.Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    String a = aliases.nextElement();
                    if (ks.isKeyEntry(a)) {
                        alias = a;
                        break;
                    }
                }
            }

            char[] keyPasswd = options.getEffectiveKeyPasswd();
            PrivateKey key = (PrivateKey) ks.getKey(alias, keyPasswd);
            Certificate[] chain = ks.getCertificateChain(alias);

            if (ArrayUtils.isEmpty(chain)) {
                LOGGER.info("Certificate chain is empty.");
                return false;
            }

            // Create DSS token from the existing key + chain
            PrivateKeySignatureToken token = new PrivateKeySignatureToken(key, chain);
            DSSPrivateKeyEntry keyEntry = token.getKeyEntry();

            // Build PAdES signature parameters
            PAdESSignatureParameters parameters = new PAdESSignatureParameters();

            final HashAlgorithm hashAlgorithm = options.getHashAlgorithm();
            DigestAlgorithm digestAlgorithm = hashAlgorithm.toDssDigestAlgorithm();

            parameters.setDigestAlgorithm(digestAlgorithm);
            parameters.setSigningCertificate(keyEntry.getCertificate());
            parameters.setCertificateChain(keyEntry.getCertificateChain());

            // Signature level: use PAdES level from config, or BASELINE_T if TSA is configured
            String tsaUrl = options.getTsaConfig().getTsaServerUrl();
            boolean useTsa = options.isTimestamp() && StringUtils.isNotEmpty(tsaUrl);
            if (useTsa) {
                parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
            } else {
                parameters.setSignatureLevel(options.getPadesLevel().getSignatureLevel());
            }

            // Signing date
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
            CertificationPermission permission = options.getCertLevel().toDssCertificationPermission();
            if (permission != null) {
                parameters.setPermission(permission);
            }

            // Password for encrypted PDFs
            String ownerPwd = options.getPdfOwnerPwdStr();
            if (StringUtils.isNotEmpty(ownerPwd)) {
                parameters.setPasswordProtection(ownerPwd.toCharArray());
            }

            // Signature size estimation
            parameters.setContentSize(30000);

            // Encrypt PDF if requested (encrypt-before-sign)
            final PDFEncryption pdfEncryption = options.getPdfEncryption();
            if (pdfEncryption == PDFEncryption.PASSWORD) {
                LOGGER.info("Setting encryption.");
                encryptedTempFile = encryptPdf(options, pdfEncryption);
                if (encryptedTempFile == null) {
                    return false;
                }
                String encOwnerPwd = options.getPdfOwnerPwdStr();
                if (StringUtils.isNotEmpty(encOwnerPwd)) {
                    parameters.setPasswordProtection(encOwnerPwd.toCharArray());
                }
            }

            // Load input document
            DSSDocument document = new FileDocument(
                    encryptedTempFile != null ? encryptedTempFile.getAbsolutePath() : options.getInFile());

            // Handle visible signature
            if (options.isVisible()) {
                LOGGER.info("Configuring visible signature.");
                configureVisibleSignature(parameters, chain, signingCal);
            }

            // Create certificate verifier
            CommonCertificateVerifier verifier = new CommonCertificateVerifier();

            // Create PAdES service
            PAdESService service = new PAdESService(verifier);

            // Configure TSA
            if (useTsa) {
                LOGGER.info("Creating TSA client.");
                TimestampDataLoader tsDataLoader = new TimestampDataLoader();
                if (options.getTsaServerAuthn() == ServerAuthentication.PASSWORD) {
                    URI tsaUri = URI.create(tsaUrl);
                    String tsaUser = options.getTsaConfig().getTsaUser();
                    String tsaPassword = options.getTsaConfig().getTsaPassword();
                    tsDataLoader.addAuthentication(tsaUri.getHost(), tsaUri.getPort(), null, tsaUser,
                            tsaPassword != null ? tsaPassword.toCharArray() : null);
                }
                OnlineTSPSource tspSource = new OnlineTSPSource(tsaUrl, tsDataLoader);

                final String policyOid = options.getTsaConfig().getTsaPolicyOid();
                if (StringUtils.isNotEmpty(policyOid)) {
                    LOGGER.info("Setting TSA policy: " + policyOid);
                    tspSource.setPolicyOid(policyOid);
                }
                if (StringUtils.isNotEmpty(options.getTsaHashAlg())) {
                    parameters.getSignatureTimestampParameters()
                            .setDigestAlgorithm(DigestAlgorithm.forJavaName(options.getTsaHashAlg()));
                }
                service.setTspSource(tspSource);
            }

            LOGGER.info("Processing signature.");

            // 3-step DSS signing
            LOGGER.info("Creating signature.");
            ToBeSigned dataToSign = service.getDataToSign(document, parameters);
            SignatureValue signatureValue = token.sign(dataToSign, digestAlgorithm, keyEntry);
            DSSDocument signedDocument = service.signDocument(document, parameters, signatureValue);

            // Write output
            LOGGER.info("Creating output PDF: " + outFile);
            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                signedDocument.writeTo(fos);
            }
            LOGGER.info("Output stream closed.");

            finished = true;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Exception during signing.", e);
        } catch (OutOfMemoryError e) {
            LOGGER.log(Level.SEVERE, "Out of memory error.", e);
        } finally {
            if (encryptedTempFile != null) {
                encryptedTempFile.delete();
            }
            LOGGER.info("Signing " + (finished ? "finished successfully." : "failed."));
        }
        return finished;
    }

    private AccessPermission buildAccessPermission(BasicConfig options) {
        AccessPermission ap = new AccessPermission();
        PrintRight printing = options.getRightPrinting();
        ap.setCanPrint(printing == PrintRight.ALLOW_PRINTING);
        ap.setCanPrintDegraded(printing != PrintRight.DISALLOW_PRINTING);
        ap.setCanExtractContent(options.isRightCopy());
        ap.setCanAssembleDocument(options.isRightAssembly());
        ap.setCanFillInForm(options.isRightFillIn());
        ap.setCanExtractForAccessibility(options.isRightScreanReaders());
        ap.setCanModifyAnnotations(options.isRightModifyAnnotations());
        ap.setCanModify(options.isRightModifyContents());
        return ap;
    }

    private File encryptPdf(BasicConfig options, PDFEncryption pdfEncryption) throws Exception {
        File inFile = new File(options.getInFile());

        try (PDDocument doc = PDDocument.load(inFile)) {
            if (!doc.getSignatureDictionaries().isEmpty()) {
                LOGGER.info("Cannot encrypt PDF with existing signatures.");
                return null;
            }

            AccessPermission ap = buildAccessPermission(options);
            StandardProtectionPolicy passwordPolicy = new StandardProtectionPolicy(
                    options.getPdfOwnerPwdStr(), options.getPdfUserPwdStr(), ap);
            passwordPolicy.setEncryptionKeyLength(128);
            doc.protect(passwordPolicy);

            File tempFile = File.createTempFile("jsignpdf-enc-", ".pdf");
            tempFile.deleteOnExit();
            doc.save(tempFile);
            return tempFile;
        }
    }

    private void configureVisibleSignature(PAdESSignatureParameters parameters,
            Certificate[] chain, Calendar signingCal) throws Exception {

        SignatureImageParameters imageParams = new SignatureImageParameters();

        // Determine page and page dimensions
        int page = options.getPage();
        float pageWidth;
        float pageHeight;
        try (PDDocument pdDoc = PDDocument.load(new File(options.getInFile()))) {
            int totalPages = pdDoc.getNumberOfPages();
            if (page < 1 || page > totalPages) {
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

        // Field position parameters
        float llx = fixPosition(options.getPositionLLX(), pageWidth);
        float lly = fixPosition(options.getPositionLLY(), pageHeight);
        float urx = fixPosition(options.getPositionURX(), pageWidth);
        float ury = fixPosition(options.getPositionURY(), pageHeight);
        float width = urx - llx;
        float height = ury - lly;

        SignatureFieldParameters fieldParams = new SignatureFieldParameters();
        fieldParams.setPage(page);
        fieldParams.setOriginX(llx);
        fieldParams.setOriginY(pageHeight - ury); // flip Y axis
        fieldParams.setWidth(width);
        fieldParams.setHeight(height);
        imageParams.setFieldParameters(fieldParams);

        // Build L2 text
        LOGGER.info("Setting L2 text.");
        X509Certificate signerCert = (X509Certificate) chain[0];
        String signer = extractCN(signerCert);
        if (StringUtils.isNotEmpty(options.getSignerName())) {
            signer = options.getSignerName();
        }
        final String certificate = signerCert.getSubjectX500Principal().toString();
        final String timestamp = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss z").format(signingCal.getTime());

        String l2text;
        if (options.getL2Text() != null) {
            final Map<String, String> replacements = new HashMap<>();
            replacements.put(L2TEXT_PLACEHOLDER_SIGNER, StringUtils.defaultString(signer));
            replacements.put(L2TEXT_PLACEHOLDER_CERTIFICATE, certificate);
            replacements.put(L2TEXT_PLACEHOLDER_TIMESTAMP, timestamp);
            replacements.put(L2TEXT_PLACEHOLDER_LOCATION, StringUtils.defaultString(options.getLocation()));
            replacements.put(L2TEXT_PLACEHOLDER_REASON, StringUtils.defaultString(options.getReason()));
            replacements.put(L2TEXT_PLACEHOLDER_CONTACT, StringUtils.defaultString(options.getContact()));
            l2text = StrSubstitutor.replace(options.getL2Text(), replacements);
        } else {
            final StringBuilder buf = new StringBuilder();
            buf.append("Signed by: ").append(signer).append('\n');
            buf.append("Date: ").append(timestamp);
            if (StringUtils.isNotEmpty(options.getReason()))
                buf.append('\n').append("Reason: ").append(options.getReason());
            if (StringUtils.isNotEmpty(options.getLocation()))
                buf.append('\n').append("Location: ").append(options.getLocation());
            l2text = buf.toString();
        }

        SignatureImageTextParameters textParams = new SignatureImageTextParameters();
        textParams.setText(l2text);

        DSSFont font = FontUtils.getL2BaseFont();
        if (font != null) {
            font.setSize(options.getL2TextFontSize());
            textParams.setFont(font);
        }
        imageParams.setTextParameters(textParams);

        // Background image
        final String bgImgPath = options.getBgImgPath();
        if (bgImgPath != null) {
            LOGGER.info("Setting background image: " + bgImgPath);
            imageParams.setImage(new FileDocument(bgImgPath));
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

    private boolean validateInOutFiles(final String inFile, final String outFile) {
        LOGGER.info("Validating input/output files.");
        if (StringUtils.isEmpty(inFile) || StringUtils.isEmpty(outFile)) {
            LOGGER.info("Input or output file is not specified.");
            return false;
        }
        final File tmpInFile = new File(inFile);
        final File tmpOutFile = new File(outFile);
        if (!(tmpInFile.exists() && tmpInFile.isFile() && tmpInFile.canRead())) {
            LOGGER.info("Input file not found or not readable: " + inFile);
            return false;
        }
        if (tmpInFile.getAbsolutePath().equals(tmpOutFile.getAbsolutePath())) {
            LOGGER.info("Input and output files are the same.");
            return false;
        }
        return true;
    }

}
