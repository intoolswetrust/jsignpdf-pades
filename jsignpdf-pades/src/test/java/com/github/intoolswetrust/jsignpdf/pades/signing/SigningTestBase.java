package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.TestConstants.Keystore;
import com.github.intoolswetrust.jsignpdf.pades.TestConstants.TestPrivateKey;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

/**
 * Abstract base class for signing integration tests. Creates a minimal PDF 1.7 document
 * using PDFBox, registers the BouncyCastle provider, and provides helper methods for
 * configuring {@link BasicConfig} and running sign-then-validate workflows.
 */
public abstract class SigningTestBase {

    private static File unsignedPdf;

    @TempDir
    Path tempDir;

    /**
     * Registers the BouncyCastle provider and generates a minimal unsigned PDF 1.7 for use
     * as signing input across all tests.
     */
    @BeforeAll
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        unsignedPdf = File.createTempFile("unsigned-", ".pdf");
        unsignedPdf.deleteOnExit();
        PDDocument doc = new PDDocument();
        doc.getDocument().setVersion(1.7f);
        PDPage page = new PDPage();
        doc.addPage(page);
        PDPageContentStream cs = new PDPageContentStream(doc, page);
        cs.beginText();
        cs.setFont(PDType1Font.HELVETICA, 12);
        cs.newLineAtOffset(100, 700);
        cs.showText("Test PDF for signing");
        cs.endText();
        cs.close();
        doc.save(unsignedPdf);
        doc.close();
    }

    /**
     * Copies the unsigned PDF into the per-test temp folder and returns configured signing options
     * for the given key and keystore.
     */
    protected BasicConfig createOptions(TestPrivateKey key, Keystore keystore) throws Exception {
        File inFile = new File(tempDir.toFile(), "input.pdf");
        Files.copy(unsignedPdf.toPath(), inFile.toPath());
        File outFile = new File(tempDir.toFile(), "output.pdf");

        BasicConfig options = key.toSignerOptions(keystore);
        options.setInFile(inFile.getAbsolutePath());
        options.setOutFile(outFile.getAbsolutePath());
        return options;
    }

    /** Creates signing options using the default key (RSA2048) and keystore (JKS). */
    protected BasicConfig createDefaultOptions() throws Exception {
        return createOptions(TestPrivateKey.RSA2048, Keystore.JKS);
    }

    /**
     * Signs a PDF using {@link SignerLogic}, asserts success, and returns the
     * {@link PdfSignatureValidator} validation result.
     */
    protected ValidationResult signAndValidate(BasicConfig options) throws Exception {
        boolean result = new SignerLogic(options).signFile();
        assertTrue(result, "Signing should succeed");
        File outFile = new File(options.getEffectiveOutFile());
        assertTrue(outFile.exists(), "Output file should exist");
        return PdfSignatureValidator.validate(outFile);
    }

    protected File getUnsignedPdf() {
        return unsignedPdf;
    }
}
