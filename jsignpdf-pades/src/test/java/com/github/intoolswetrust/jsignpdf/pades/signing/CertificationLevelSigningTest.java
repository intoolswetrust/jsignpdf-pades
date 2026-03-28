package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.types.CertificationLevel;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

/**
 * Tests that all {@link CertificationLevel} values produce valid signatures.
 */
public class CertificationLevelSigningTest extends SigningTestBase {

    /** Signs with {@link CertificationLevel#NOT_CERTIFIED} (default, approval signature). */
    @Test
    public void testNotCertified() throws Exception {
        assertCertificationLevel(CertificationLevel.NOT_CERTIFIED);
    }

    /** Signs with certification that disallows any subsequent changes. */
    @Test
    public void testCertifiedNoChanges() throws Exception {
        assertCertificationLevel(CertificationLevel.CERTIFIED_NO_CHANGES_ALLOWED);
    }

    /** Signs with certification that allows form filling only. */
    @Test
    public void testCertifiedFormFilling() throws Exception {
        assertCertificationLevel(CertificationLevel.CERTIFIED_FORM_FILLING);
    }

    /** Signs with certification that allows form filling and annotations. */
    @Test
    public void testCertifiedFormFillingAndAnnotations() throws Exception {
        assertCertificationLevel(CertificationLevel.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS);
    }

    private void assertCertificationLevel(CertificationLevel level) throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setCertLevel(level);
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid for " + level);
        assertEquals(1, result.signatureCount, "Should have 1 signature");

        if (level == CertificationLevel.NOT_CERTIFIED) {
            assertFalse(result.isCertified, "NOT_CERTIFIED should not have DocMDP");
        } else {
            assertTrue(result.isCertified, level + " should have DocMDP");
            assertEquals(level.getLevel(), result.docMdpPermission,
                    "DocMDP permission should match for " + level);
        }
    }
}
