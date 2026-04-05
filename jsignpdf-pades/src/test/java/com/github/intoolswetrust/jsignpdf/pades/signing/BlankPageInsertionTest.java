package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.VisibleSignatureConfig;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

public class BlankPageInsertionTest extends SigningTestBase {

    @Test
    void testBlankPageAdded() throws Exception {
        BasicConfig options = createDefaultOptions();

        int originalPageCount;
        try (PDDocument doc = Loader.loadPDF(inputFile)) {
            originalPageCount = doc.getNumberOfPages();
        }
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setAddBlankPage(true);
        visConfig.setPositionLLX(50);
        visConfig.setPositionLLY(50);
        visConfig.setPositionURX(250);
        visConfig.setPositionURY(120);

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");

        try (PDDocument signedDoc = Loader.loadPDF(outputFile)) {
            assertEquals(originalPageCount + 1, signedDoc.getNumberOfPages(),
                    "Signed PDF should have one more page than original");
        }
    }

    @Test
    void testBlankPageSignatureOnLastPage() throws Exception {
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setAddBlankPage(true);
        visConfig.setPositionLLX(50);
        visConfig.setPositionLLY(50);
        visConfig.setPositionURX(250);
        visConfig.setPositionURY(120);

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertTrue(result.hasVisibleRect, "Should have visible rect");

        try (PDDocument signedDoc = Loader.loadPDF(outputFile)) {
            int lastPage = signedDoc.getNumberOfPages();
            assertEquals(lastPage, result.signaturePage,
                    "Signature should be on the last (blank) page");
        }
    }

    @Test
    void testBlankPageWithoutVisibleSignature() throws Exception {
        // addBlankPage without visible=true should not add a page
        BasicConfig options = createDefaultOptions();

        int originalPageCount;
        try (PDDocument doc = Loader.loadPDF(inputFile)) {
            originalPageCount = doc.getNumberOfPages();
        }

        options.getVisibleSignatureConfig().setAddBlankPage(true); // but visible is false

        boolean success = new SignerLogic(options).signFile(inputFile, outputFile);
        assertTrue(success, "Signing should succeed");

        try (PDDocument signedDoc = Loader.loadPDF(outputFile)) {
            assertEquals(originalPageCount, signedDoc.getNumberOfPages(),
                    "Page count should not change when visible signature is not enabled");
        }
    }

    @Test
    void testBlankPageWithCustomText() throws Exception {
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setAddBlankPage(true);
        visConfig.setPositionLLX(50);
        visConfig.setPositionLLY(50);
        visConfig.setPositionURX(300);
        visConfig.setPositionURY(150);
        visConfig.setText("Signed on blank page by ${signer}");

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertNotNull(result.appearanceText, "Appearance text should be present");
        assertTrue(result.appearanceText.contains("Signed on blank page by"),
                "Custom text should be in appearance");
    }
}
