package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.types.PrintRight;

/**
 * Tests the printing permissions written into an encrypt-before-sign PDF, over the whole {@link PrintRight}
 * truth table. The two PDF permission bits are independent — {@code canPrint} allows printing at all, and
 * {@code canPrintFaithful} allows it at full resolution — so degraded printing is the case that tells a correct
 * mapping apart from an inverted one.
 */
public class PrintRightSigningTest extends SigningTestBase {

    private static final char[] OWNER_PASSWORD = "ownerpass".toCharArray();
    private static final char[] USER_PASSWORD = "userpass".toCharArray();

    @Test
    public void testAllowPrinting() throws Exception {
        AccessPermission permission = signWithPrintRight(PrintRight.ALLOW_PRINTING);

        assertTrue(permission.canPrint(), "Printing should be allowed");
        assertTrue(permission.canPrintFaithful(), "High-resolution printing should be allowed");
    }

    @Test
    public void testAllowDegradedPrinting() throws Exception {
        AccessPermission permission = signWithPrintRight(PrintRight.ALLOW_DEGRADED_PRINTING);

        assertTrue(permission.canPrint(), "Degraded printing still allows printing");
        assertFalse(permission.canPrintFaithful(), "Degraded printing must not allow high-resolution printing");
    }

    @Test
    public void testDisallowPrinting() throws Exception {
        AccessPermission permission = signWithPrintRight(PrintRight.DISALLOW_PRINTING);

        assertFalse(permission.canPrint(), "Printing should be disallowed");
        assertFalse(permission.canPrintFaithful(), "High-resolution printing should be disallowed");
    }

    /**
     * Encrypts and signs with the given printing right, then reads the permissions back through the user
     * password — the owner password grants full access per the PDF spec, so it would mask the restrictions.
     */
    private AccessPermission signWithPrintRight(PrintRight printRight) throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setEncryptBeforeSign(true);
        options.setPdfOwnerPwd(OWNER_PASSWORD);
        options.setPdfUserPwd(USER_PASSWORD);
        options.setRightPrinting(printRight);

        assertTrue(new SignerLogic(options).signFile(inputFile, outputFile), "Signing should succeed");

        try (PDDocument doc = Loader.loadPDF(outputFile, new String(USER_PASSWORD))) {
            assertTrue(doc.isEncrypted(), "Output PDF should be encrypted");
            assertEquals(1, doc.getSignatureDictionaries().size(), "Output PDF should carry one signature");
            return doc.getCurrentAccessPermission();
        }
    }
}
