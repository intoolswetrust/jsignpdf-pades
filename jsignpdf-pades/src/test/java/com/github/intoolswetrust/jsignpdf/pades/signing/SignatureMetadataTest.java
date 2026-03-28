package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

/**
 * Tests that signature metadata (reason, location, contact, sign date) is correctly
 * embedded in the PDF signature dictionary and can be read back from the signed PDF.
 */
public class SignatureMetadataTest extends SigningTestBase {

    /** Verifies that the reason field is stored in the signature dictionary. */
    @Test
    public void testReason() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setReason("Test signing reason");
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertEquals("Test signing reason", result.reason, "Reason should match");
    }

    /** Verifies that the location field is stored in the signature dictionary. */
    @Test
    public void testLocation() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setLocation("Test Location City");
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertEquals("Test Location City", result.location, "Location should match");
    }

    /** Verifies that the contact field is stored in the signature dictionary. */
    @Test
    public void testContact() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setContact("test@example.com");
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertEquals("test@example.com", result.contactInfo, "Contact should match");
    }

    /** Verifies that reason, location, and contact can all be set together. */
    @Test
    public void testAllMetadata() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setReason("Combined reason");
        options.setLocation("Combined location");
        options.setContact("combined@example.com");
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertEquals("Combined reason", result.reason, "Reason should match");
        assertEquals("Combined location", result.location, "Location should match");
        assertEquals("combined@example.com", result.contactInfo, "Contact should match");
    }

    /** Verifies that metadata fields are absent when not configured. */
    @Test
    public void testEmptyMetadata() throws Exception {
        BasicConfig options = createDefaultOptions();
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertNull(result.reason, "Reason should be null");
        assertNull(result.location, "Location should be null");
        assertNull(result.contactInfo, "Contact should be null");
    }

    /** Verifies that the signing date is present in the signature dictionary. */
    @Test
    public void testSignDate() throws Exception {
        BasicConfig options = createDefaultOptions();
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertNotNull(result.signDate, "Sign date should be present");
    }
}
