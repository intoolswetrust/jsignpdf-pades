package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.types.PDFEncryption;

/**
 * Tests that {@link PDFEncryption#NONE} does not encrypt the output PDF.
 */
public class PdfEncryptionNoneTest extends SigningTestBase {

    @Test
    public void testEncryptionNoneProducesUnencryptedOutput() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setPdfEncryption(PDFEncryption.NONE);

        boolean success = new SignerLogic(options).signFile(inputFile, outputFile);
        assertTrue(success, "Signing should succeed with NONE encryption");

        try (PDDocument doc = PDDocument.load(outputFile)) {
            assertFalse(doc.isEncrypted(), "Output should not be encrypted when PDFEncryption is NONE");
        }
    }

    @Test
    public void testNullEncryptionProducesUnencryptedOutput() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setPdfEncryption(null);

        boolean success = new SignerLogic(options).signFile(inputFile, outputFile);
        assertTrue(success, "Signing should succeed with null encryption");

        try (PDDocument doc = PDDocument.load(outputFile)) {
            assertFalse(doc.isEncrypted(), "Output should not be encrypted when PDFEncryption is null");
        }
    }
}
