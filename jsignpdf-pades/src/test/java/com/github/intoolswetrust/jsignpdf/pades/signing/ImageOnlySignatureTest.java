package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import java.awt.image.BufferedImage;
import java.io.File;

import javax.imageio.ImageIO;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.VisibleSignatureConfig;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

public class ImageOnlySignatureTest extends SigningTestBase {

    private File createTestImage() throws Exception {
        File imgFile = new File(tempDir.toFile(), "logo.png");
        BufferedImage img = new BufferedImage(100, 50, BufferedImage.TYPE_INT_ARGB);
        java.awt.Graphics2D g = img.createGraphics();
        g.setColor(java.awt.Color.BLUE);
        g.fillRect(0, 0, 100, 50);
        g.setColor(java.awt.Color.WHITE);
        g.drawString("SIGN", 30, 30);
        g.dispose();
        ImageIO.write(img, "PNG", imgFile);
        return imgFile;
    }

    @Test
    void testImageOnlySignature() throws Exception {
        File logo = createTestImage();

        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setImageOnly(true);
        visConfig.setPage(1);
        visConfig.setPositionLLX(50);
        visConfig.setPositionLLY(50);
        visConfig.setPositionURX(200);
        visConfig.setPositionURY(120);
        visConfig.setBgImgPath(logo.getAbsolutePath());

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertTrue(result.hasVisibleRect, "Should have visible rect");
        assertEquals(1, result.signaturePage, "Signature should be on page 1");
    }

    @Test
    void testImageOnlyHasNoText() throws Exception {
        File logo = createTestImage();

        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setImageOnly(true);
        visConfig.setPage(1);
        visConfig.setPositionLLX(50);
        visConfig.setPositionLLY(50);
        visConfig.setPositionURX(200);
        visConfig.setPositionURY(120);
        visConfig.setBgImgPath(logo.getAbsolutePath());
        options.setReason("ShouldNotAppear");

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        // In image-only mode, there should be no L2 text in the appearance
        if (result.appearanceText != null) {
            assertFalse(result.appearanceText.contains("ShouldNotAppear"),
                    "Image-only mode should not include text content");
            assertFalse(result.appearanceText.contains("Signed by"),
                    "Image-only mode should not include default L2 text");
        }
    }

    @Test
    void testImageOnlyWithoutImage() throws Exception {
        // Image-only without an actual image — signature is valid but has no visible content
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setImageOnly(true);
        visConfig.setPage(1);
        visConfig.setPositionLLX(50);
        visConfig.setPositionLLY(50);
        visConfig.setPositionURX(200);
        visConfig.setPositionURY(120);
        // No bgImgPath set — no image and no text means empty appearance

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid even without image");
    }

    @Test
    void testNonImageOnlyStillHasText() throws Exception {
        // Verify that without imageOnly flag, text is present
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setPage(1);
        visConfig.setPositionLLX(50);
        visConfig.setPositionLLY(50);
        visConfig.setPositionURX(250);
        visConfig.setPositionURY(120);
        options.setReason("TextShouldAppear");

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertNotNull(result.appearanceText, "Non-image-only should have text");
        assertTrue(result.appearanceText.contains("TextShouldAppear"),
                "Text should be present in normal mode");
    }

    @Test
    void testImageOnlyWithBlankPage() throws Exception {
        File logo = createTestImage();

        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setImageOnly(true);
        visConfig.setAddBlankPage(true);
        visConfig.setPositionLLX(100);
        visConfig.setPositionLLY(300);
        visConfig.setPositionURX(300);
        visConfig.setPositionURY(400);
        visConfig.setBgImgPath(logo.getAbsolutePath());

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertTrue(result.hasVisibleRect, "Should have visible rect");
        // Signature should be on the last (blank) page
        assertTrue(result.signaturePage > 1, "Signature should be on the added blank page");
    }
}
