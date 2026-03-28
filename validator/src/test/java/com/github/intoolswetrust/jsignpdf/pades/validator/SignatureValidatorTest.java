package com.github.intoolswetrust.jsignpdf.pades.validator;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Security;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.intoolswetrust.jsignpdf.pades.validator.config.ValidatorConfig;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;

public class SignatureValidatorTest {

    @TempDir
    Path tempDir;

    private static final String KS_FILE = "src/test/resources/test-keystore.jks";
    private static final String KS_PASSWORD = "keystorepass";
    private static final String KEY_ALIAS = "rsa2048";
    private static final String KEY_PASSWORD = "RSA2048pass";

    @BeforeAll
    static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Helper: create unsigned PDF
    private File createUnsignedPdf() throws Exception {
        File pdf = new File(tempDir.toFile(), "unsigned.pdf");
        try (PDDocument doc = new PDDocument()) {
            doc.setVersion(1.7f);
            PDPage page = new PDPage();
            doc.addPage(page);
            try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
                cs.beginText();
                cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                cs.newLineAtOffset(100, 700);
                cs.showText("Test PDF for validation");
                cs.endText();
            }
            doc.save(pdf);
        }
        return pdf;
    }

    // Helper: sign a PDF using DSS directly
    private File signPdf(File inputPdf, SignatureLevel level) throws Exception {
        File outputPdf = new File(tempDir.toFile(), "signed-" + level.name() + ".pdf");

        try (FileInputStream fis = new FileInputStream(KS_FILE)) {
            KeyStoreSignatureTokenConnection token = new KeyStoreSignatureTokenConnection(
                    fis, "JKS", new KeyStore.PasswordProtection(KS_PASSWORD.toCharArray()));

            DSSPrivateKeyEntry keyEntry = token.getKey(KEY_ALIAS,
                    new KeyStore.PasswordProtection(KEY_PASSWORD.toCharArray()));

            PAdESSignatureParameters params = new PAdESSignatureParameters();
            params.setSignatureLevel(level);
            params.setDigestAlgorithm(DigestAlgorithm.SHA256);
            params.setSigningCertificate(keyEntry.getCertificate());
            params.setCertificateChain(keyEntry.getCertificateChain());

            CommonCertificateVerifier verifier = new CommonCertificateVerifier();
            PAdESService service = new PAdESService(verifier);

            DSSDocument toSign = new FileDocument(inputPdf);
            ToBeSigned dataToSign = service.getDataToSign(toSign, params);
            SignatureValue signatureValue = token.sign(dataToSign, DigestAlgorithm.SHA256, keyEntry);
            DSSDocument signedDoc = service.signDocument(toSign, params, signatureValue);

            try (FileOutputStream fos = new FileOutputStream(outputPdf)) {
                signedDoc.writeTo(fos);
            }
            token.close();
        }
        return outputPdf;
    }

    private ValidatorConfig createConfig() {
        return new ValidatorConfig();
    }

    @Test
    void testValidateSignedPdf() throws Exception {
        File unsigned = createUnsignedPdf();
        File signed = signPdf(unsigned, SignatureLevel.PAdES_BASELINE_B);

        SignatureValidator validator = new SignatureValidator(createConfig());
        ValidationResult result = validator.validate(signed);

        assertTrue(result.getSignatureCount() > 0, "Should find signatures");
        assertEquals(1, result.getSignatureCount(), "Should have 1 signature");
    }

    @Test
    void testValidateUnsignedPdf() throws Exception {
        File unsigned = createUnsignedPdf();

        SignatureValidator validator = new SignatureValidator(createConfig());
        ValidationResult result = validator.validate(unsigned);

        assertEquals(0, result.getSignatureCount(), "Unsigned PDF should have 0 signatures");
        assertFalse(result.isAllValid(), "Unsigned PDF should not be valid");
    }

    @Test
    void testValidateMultipleSignatures() throws Exception {
        File unsigned = createUnsignedPdf();
        File signed1 = signPdf(unsigned, SignatureLevel.PAdES_BASELINE_B);
        // Sign again (second signature)
        File signed2 = signPdf(signed1, SignatureLevel.PAdES_BASELINE_B);

        SignatureValidator validator = new SignatureValidator(createConfig());
        ValidationResult result = validator.validate(signed2);

        assertEquals(2, result.getSignatureCount(), "Should have 2 signatures");
    }

    @Test
    void testXmlSimpleReportNotEmpty() throws Exception {
        File unsigned = createUnsignedPdf();
        File signed = signPdf(unsigned, SignatureLevel.PAdES_BASELINE_B);

        SignatureValidator validator = new SignatureValidator(createConfig());
        ValidationResult result = validator.validate(signed);

        String xml = result.getXmlSimpleReport();
        assertNotNull(xml, "XML simple report should not be null");
        assertTrue(xml.contains("SimpleReport"), "Should contain SimpleReport element");
    }

    @Test
    void testEtsiReportNotEmpty() throws Exception {
        File unsigned = createUnsignedPdf();
        File signed = signPdf(unsigned, SignatureLevel.PAdES_BASELINE_B);

        SignatureValidator validator = new SignatureValidator(createConfig());
        ValidationResult result = validator.validate(signed);

        String etsi = result.getXmlEtsiReport();
        assertNotNull(etsi, "ETSI report should not be null");
        assertTrue(etsi.length() > 0, "ETSI report should not be empty");
    }

    @Test
    void testSignerIdentity() throws Exception {
        File unsigned = createUnsignedPdf();
        File signed = signPdf(unsigned, SignatureLevel.PAdES_BASELINE_B);

        SignatureValidator validator = new SignatureValidator(createConfig());
        ValidationResult result = validator.validate(signed);

        String signedBy = result.getSimpleReport().getSignedBy(
                result.getSimpleReport().getFirstSignatureId());
        assertNotNull(signedBy, "Signer identity should be present");
        assertTrue(signedBy.length() > 0, "Signer identity should not be empty");
    }
}
