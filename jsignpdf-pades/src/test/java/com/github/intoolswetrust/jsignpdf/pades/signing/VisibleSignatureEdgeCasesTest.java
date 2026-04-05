package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.image.BufferedImage;
import java.io.File;

import javax.imageio.ImageIO;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.VisibleSignatureConfig;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

/**
 * Tests for edge cases in visible signature configuration.
 */
public class VisibleSignatureEdgeCasesTest extends SigningTestBase {

    @Test
    public void testVisibleSignatureWithSignerNameOverride() throws Exception {
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        options.setSignerName("Custom Signer Name");
        visConfig.setText("Signed by: ${signer}");
        visConfig.setPositionLLX(0);
        visConfig.setPositionLLY(0);
        visConfig.setPositionURX(200);
        visConfig.setPositionURY(50);

        ValidationResult result = signAndValidate(options);
        assertEquals(1, result.signatureCount, "Should have 1 signature");
        assertTrue(result.signatureValid, "Signature should be valid");
    }

    @Test
    public void testVisibleSignatureWithPageBeyondTotal() throws Exception {
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setPage(999);
        visConfig.setPositionLLX(0);
        visConfig.setPositionLLY(0);
        visConfig.setPositionURX(200);
        visConfig.setPositionURY(50);

        ValidationResult result = signAndValidate(options);
        assertEquals(1, result.signatureCount, "Should have 1 signature");
        assertTrue(result.signatureValid, "Signature should be valid even with out-of-range page");
    }

    @Test
    public void testVisibleSignatureWithPageZero() throws Exception {
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setPage(0);
        visConfig.setPositionLLX(0);
        visConfig.setPositionLLY(0);
        visConfig.setPositionURX(200);
        visConfig.setPositionURY(50);

        ValidationResult result = signAndValidate(options);
        assertEquals(1, result.signatureCount, "Should have 1 signature");
        assertTrue(result.signatureValid, "Signature should be valid even with page 0");
    }

    @Test
    public void testVisibleSignatureWithReasonAndLocation() throws Exception {
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        options.setReason("Test Reason");
        options.setLocation("Test Location");
        visConfig.setPositionLLX(0);
        visConfig.setPositionLLY(0);
        visConfig.setPositionURX(200);
        visConfig.setPositionURY(50);

        ValidationResult result = signAndValidate(options);
        assertEquals(1, result.signatureCount, "Should have 1 signature");
        assertTrue(result.signatureValid, "Signature should be valid");
    }

    @Test
    public void testVisibleSignatureWithBackgroundImage() throws Exception {
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setPositionLLX(0);
        visConfig.setPositionLLY(0);
        visConfig.setPositionURX(200);
        visConfig.setPositionURY(50);

        // Create a minimal 1x1 PNG in the temp directory
        File bgImage = new File(tempDir.toFile(), "bg.png");
        BufferedImage img = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
        img.setRGB(0, 0, 0xFFFFFF);
        ImageIO.write(img, "png", bgImage);

        visConfig.setBgImgPath(bgImage.getAbsolutePath());

        ValidationResult result = signAndValidate(options);
        assertEquals(1, result.signatureCount, "Should have 1 signature");
        assertTrue(result.signatureValid, "Signature should be valid with background image");
    }
}
