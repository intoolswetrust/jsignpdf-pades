package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.VisibleSignatureConfig;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

/**
 * Tests visible and invisible signature configurations. Verifies that the signature is
 * cryptographically valid and that visual attributes (page, position, appearance text)
 * are correctly embedded in the signed PDF.
 */
public class VisibleSignatureSigningTest extends SigningTestBase {

    /** Verifies that the default invisible signature has no visible widget rectangle. */
    @Test
    public void testInvisibleDefault() throws Exception {
        BasicConfig options = createDefaultOptions();
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertEquals(1, result.signatureCount, "Should have 1 signature");
        assertFalse(result.hasVisibleRect, "Invisible signature should have no visible rect");
    }

    /** Verifies that a visible signature is placed at the configured rectangle coordinates on the correct page. */
    @Test
    public void testVisibleWithPosition() throws Exception {
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setPage(1);
        visConfig.setPositionLLX(50);
        visConfig.setPositionLLY(60);
        visConfig.setPositionURX(200);
        visConfig.setPositionURY(110);
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertTrue(result.hasVisibleRect, "Should have visible rect");
        assertEquals(1, result.signaturePage, "Signature should be on page 1");
        assertEquals(50f, result.rectLLX, 1f, "LLX should match");
        assertEquals(60f, result.rectLLY, 1f, "LLY should match");
        assertEquals(200f, result.rectURX, 1f, "URX should match");
        assertEquals(110f, result.rectURY, 1f, "URY should match");
    }

    /** Verifies that custom L2 text with placeholder substitution appears in the appearance stream. */
    @Test
    public void testVisibleWithCustomL2Text() throws Exception {
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setPage(1);
        visConfig.setPositionLLX(50);
        visConfig.setPositionLLY(50);
        visConfig.setPositionURX(250);
        visConfig.setPositionURY(120);
        options.setReason("TestReason");
        options.setLocation("TestLocation");
        visConfig.setText("Signed by ${signer}, reason: ${reason}, loc: ${location}");
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertNotNull(result.appearanceText, "Appearance text should be present");
        assertTrue(result.appearanceText.contains("TestReason"),
                "L2 text should contain reason value");
        assertTrue(result.appearanceText.contains("TestLocation"),
                "L2 text should contain location value");
        assertFalse(result.appearanceText.contains("${signer}"),
                "Signer placeholder should be substituted");
        assertFalse(result.appearanceText.contains("${reason}"),
                "Reason placeholder should be substituted");
    }

    /** Verifies that all L2 text placeholders are substituted with actual values. */
    @Test
    public void testVisibleWithAllPlaceholders() throws Exception {
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setPage(1);
        visConfig.setPositionLLX(10);
        visConfig.setPositionLLY(10);
        visConfig.setPositionURX(300);
        visConfig.setPositionURY(150);
        options.setReason("AllReason");
        options.setLocation("AllLocation");
        options.setContact("all@contact.com");
        visConfig.setText("S:${signer} R:${reason} L:${location} C:${contact} T:${timestamp}");
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertNotNull(result.appearanceText, "Appearance text should be present");
        assertTrue(result.appearanceText.contains("AllReason"), "Should contain reason");
        assertTrue(result.appearanceText.contains("AllLocation"), "Should contain location");
        assertTrue(result.appearanceText.contains("all@contact.com"), "Should contain contact");
        assertFalse(result.appearanceText.contains("${timestamp}"),
                "Timestamp placeholder should be substituted");
    }

    /** Verifies that the default L2 text (no custom template) contains signer information. */
    @Test
    public void testDefaultL2TextContainsSignerInfo() throws Exception {
        BasicConfig options = createDefaultOptions();
        VisibleSignatureConfig visConfig = options.getVisibleSignatureConfig();
        visConfig.setVisible(true);
        visConfig.setPage(1);
        visConfig.setPositionLLX(50);
        visConfig.setPositionLLY(50);
        visConfig.setPositionURX(250);
        visConfig.setPositionURY(120);
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertNotNull(result.appearanceText, "Appearance text should be present");
        assertTrue(result.appearanceText.length() > 0, "Default L2 text should not be empty");
    }
}
