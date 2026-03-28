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

import com.github.intoolswetrust.jsignpdf.pades.validator.config.OutputFormat;
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

public class ValidationOutputTest {

    @TempDir
    Path tempDir;

    @BeforeAll
    static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private ValidationResult createSignedResult() throws Exception {
        // Create and sign a PDF
        File pdf = new File(tempDir.toFile(), "test.pdf");
        try (PDDocument doc = new PDDocument()) {
            doc.setVersion(1.7f);
            PDPage page = new PDPage();
            doc.addPage(page);
            try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
                cs.beginText();
                cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                cs.newLineAtOffset(100, 700);
                cs.showText("Output format test");
                cs.endText();
            }
            doc.save(pdf);
        }

        File signed = new File(tempDir.toFile(), "signed.pdf");
        try (FileInputStream fis = new FileInputStream("src/test/resources/test-keystore.jks")) {
            KeyStoreSignatureTokenConnection token = new KeyStoreSignatureTokenConnection(
                    fis, "JKS", new KeyStore.PasswordProtection("keystorepass".toCharArray()));
            DSSPrivateKeyEntry keyEntry = token.getKey("rsa2048",
                    new KeyStore.PasswordProtection("RSA2048pass".toCharArray()));

            PAdESSignatureParameters params = new PAdESSignatureParameters();
            params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
            params.setDigestAlgorithm(DigestAlgorithm.SHA256);
            params.setSigningCertificate(keyEntry.getCertificate());
            params.setCertificateChain(keyEntry.getCertificateChain());

            PAdESService service = new PAdESService(new CommonCertificateVerifier());
            DSSDocument toSign = new FileDocument(pdf);
            ToBeSigned dataToSign = service.getDataToSign(toSign, params);
            SignatureValue sigVal = token.sign(dataToSign, DigestAlgorithm.SHA256, keyEntry);
            DSSDocument signedDoc = service.signDocument(toSign, params, sigVal);
            try (FileOutputStream fos = new FileOutputStream(signed)) {
                signedDoc.writeTo(fos);
            }
            token.close();
        }

        SignatureValidator validator = new SignatureValidator(new ValidatorConfig());
        return validator.validate(signed);
    }

    @Test
    void testTextFormat() throws Exception {
        ValidationResult result = createSignedResult();
        String text = ValidationOutput.format(result, OutputFormat.TEXT, false);
        assertNotNull(text);
        assertTrue(text.contains("Signatures:"), "Should contain signature count");
        assertTrue(text.contains("Result:"), "Should contain result");
    }

    @Test
    void testTextFormatVerbose() throws Exception {
        ValidationResult result = createSignedResult();
        String text = ValidationOutput.format(result, OutputFormat.TEXT, true);
        assertNotNull(text);
        assertTrue(text.contains("Signatures:"), "Should contain signature count");
    }

    @Test
    void testXmlFormat() throws Exception {
        ValidationResult result = createSignedResult();
        String xml = ValidationOutput.format(result, OutputFormat.XML, false);
        assertNotNull(xml);
        assertTrue(xml.startsWith("<?xml") || xml.contains("SimpleReport"),
                "Should be XML content");
    }

    @Test
    void testEtsiFormat() throws Exception {
        ValidationResult result = createSignedResult();
        String etsi = ValidationOutput.format(result, OutputFormat.ETSI, false);
        assertNotNull(etsi);
        assertTrue(etsi.length() > 0, "ETSI report should not be empty");
    }

    @Test
    void testJsonFormat() throws Exception {
        ValidationResult result = createSignedResult();
        String json = ValidationOutput.format(result, OutputFormat.JSON, false);
        assertNotNull(json);
        assertTrue(json.contains("\"signaturesCount\""), "Should contain signaturesCount");
        assertTrue(json.contains("\"valid\""), "Should contain valid field");
        assertTrue(json.contains("\"signatures\""), "Should contain signatures array");
    }
}
