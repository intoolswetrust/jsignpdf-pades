package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.TestConstants;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;
import com.github.intoolswetrust.jsignpdf.pades.types.PrintRight;

/**
 * Tests signing of password-protected PDF documents and PDF output encryption
 * (encrypt-before-sign). Verifies that the DSS PAdES signing flow correctly
 * handles PDFs encrypted with owner/user passwords via
 * {@code PAdESSignatureParameters.setPasswordProtection(char[])} and that
 * {@link SignerLogic} can encrypt a plain PDF before signing it.
 */
public class PasswordProtectedPdfSigningTest extends SigningTestBase {

    private static final char[] OWNER_PASSWORD = "ownerTestPassword".toCharArray();
    private static final char[] USER_PASSWORD = "userTestPassword".toCharArray();

    /** Signs a PDF protected with only an owner password. */
    @Test
    public void testSignWithOwnerPassword() throws Exception {
        File protectedPdf = createPasswordProtectedPdf(new String(OWNER_PASSWORD), "");
        BasicConfig options = createDefaultOptions();
        this.inputFile = protectedPdf;
        options.setPdfOwnerPwd(OWNER_PASSWORD);

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertEquals(1, result.signatureCount, "Should have 1 signature");
    }

    /** Signs a PDF protected with both owner and user passwords. */
    @Test
    public void testSignWithOwnerAndUserPassword() throws Exception {
        File protectedPdf = createPasswordProtectedPdf(new String(OWNER_PASSWORD), new String(USER_PASSWORD));
        BasicConfig options = createDefaultOptions();
        this.inputFile = protectedPdf;
        options.setPdfOwnerPwd(OWNER_PASSWORD);

        boolean success = new SignerLogic(options).signFile(inputFile, outputFile);
        assertTrue(success, "Signing should succeed");
        assertTrue(outputFile.exists(), "Output file should exist");

        // The signed output retains PDF encryption, so the validator needs a password
        ValidationResult result = PdfSignatureValidator.validate(outputFile, new String(OWNER_PASSWORD));

        assertTrue(result.signatureValid, "Signature should be valid");
        assertEquals(1, result.signatureCount, "Should have 1 signature");
    }

    /** Signing a password-protected PDF without providing the password should fail. */
    @Test
    public void testSignWithoutPasswordFails() throws Exception {
        File protectedPdf = createPasswordProtectedPdf(new String(OWNER_PASSWORD), new String(USER_PASSWORD));
        BasicConfig options = createDefaultOptions();
        this.inputFile = protectedPdf;
        // Do not set pdfOwnerPwd

        boolean success = new SignerLogic(options).signFile(inputFile, outputFile);
        assertFalse(success, "Signing should fail without password");
    }

    /** Full structural validation of a signed password-protected PDF. */
    @Test
    public void testSignedOutputHasValidStructure() throws Exception {
        File protectedPdf = createPasswordProtectedPdf(new String(OWNER_PASSWORD), "");
        BasicConfig options = createDefaultOptions();
        this.inputFile = protectedPdf;
        options.setPdfOwnerPwd(OWNER_PASSWORD);

        ValidationResult result = signAndValidate(options);

        assertEquals("ETSI.CAdES.detached", result.subFilter, "SubFilter should be ETSI.CAdES.detached");
        assertTrue(result.byteRangeStartsAtZero, "ByteRange should start at 0");
        assertTrue(result.byteRangeEndsAtEof, "ByteRange should end at EOF");
        assertTrue(result.byteRangeHasGap, "ByteRange should have gap for Contents");
        assertEquals(1, result.cmsSignerCount, "CMS should have 1 signer");
        assertTrue(result.certificateCount > 0, "Certificate should be present");
        assertTrue(result.signatureValid, "Signature should be cryptographically valid");
    }

    // --- Encrypt-before-sign tests ---

    /** Encrypts an unprotected PDF with PASSWORD encryption then signs it. */
    @Test
    public void testPasswordEncryptionBeforeSigning() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setEncryptBeforeSign(true);
        options.setPdfOwnerPwd(OWNER_PASSWORD);
        options.setPdfUserPwd(USER_PASSWORD);

        boolean success = new SignerLogic(options).signFile(inputFile, outputFile);
        assertTrue(success, "Signing with password encryption should succeed");
        assertTrue(outputFile.exists(), "Output file should exist");

        // Output should be encrypted — loading without password should fail or report encrypted
        try (PDDocument doc = Loader.loadPDF(outputFile, new String(OWNER_PASSWORD))) {
            assertTrue(doc.isEncrypted(), "Output PDF should be encrypted");
        }

        // Validate signature with the owner password
        ValidationResult result = PdfSignatureValidator.validate(outputFile, new String(OWNER_PASSWORD));
        assertTrue(result.signatureValid, "Signature should be valid");
        assertEquals(1, result.signatureCount, "Should have 1 signature");
    }

    /** Attempting to encrypt a PDF that already has signatures should fail. */
    @Test
    public void testEncryptionBlockedWhenExistingSignatures() throws Exception {
        // First, sign the PDF normally
        BasicConfig options1 = createDefaultOptions();
        boolean success1 = new SignerLogic(options1).signFile(inputFile, outputFile);
        assertTrue(success1, "First signing should succeed");
        assertTrue(outputFile.exists(), "Signed PDF should exist");

        // Now try to encrypt+sign the already-signed PDF
        BasicConfig options2 = TestConstants.TestPrivateKey.RSA2048.toSignerOptions(TestConstants.Keystore.JKS);
        File secondInput = outputFile;
        File secondOutput = new File(tempDir.toFile(), "output2.pdf");
        options2.setEncryptBeforeSign(true);
        options2.setPdfOwnerPwd("owner".toCharArray());
        options2.setPdfUserPwd("user".toCharArray());

        boolean success2 = new SignerLogic(options2).signFile(secondInput, secondOutput);
        assertFalse(success2, "Encrypting an already-signed PDF should fail");
    }

    /** Encrypts a PDF with restricted permissions and verifies them in the output. */
    @Test
    public void testEncryptionWithPermissions() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setEncryptBeforeSign(true);
        options.setPdfOwnerPwd(OWNER_PASSWORD);
        options.setPdfUserPwd(USER_PASSWORD);
        options.setRightPrinting(PrintRight.DISALLOW_PRINTING);
        options.setDisableCopy(true);
        options.setDisableModifyContent(true);

        boolean success = new SignerLogic(options).signFile(inputFile, outputFile);
        assertTrue(success, "Signing with permissions should succeed");

        // Validate signature is cryptographically valid
        ValidationResult result = PdfSignatureValidator.validate(outputFile, new String(OWNER_PASSWORD));
        assertTrue(result.signatureValid, "Signature should be valid");
        assertEquals(1, result.signatureCount, "Should have 1 signature");

        // Load with the user password to see restricted permissions
        // (owner password grants full access per PDF spec)
        try (PDDocument doc = Loader.loadPDF(outputFile, new String(USER_PASSWORD))) {
            assertTrue(doc.isEncrypted(), "Output PDF should be encrypted");
            AccessPermission ap = doc.getCurrentAccessPermission();
            assertFalse(ap.canPrint(), "Printing should be disallowed");
            assertFalse(ap.canExtractContent(), "Content extraction should be disallowed");
            assertFalse(ap.canModify(), "Modification should be disallowed");
        }
    }

    // --- Helper methods ---

    /**
     * Creates a minimal password-protected PDF using PDFBox {@link StandardProtectionPolicy}.
     */
    private File createPasswordProtectedPdf(String ownerPassword, String userPassword) throws Exception {
        File protectedPdf = new File(tempDir.toFile(), "protected.pdf");
        PDDocument doc = new PDDocument();
        doc.setVersion(1.7f);
        PDPage page = new PDPage();
        doc.addPage(page);
        PDPageContentStream cs = new PDPageContentStream(doc, page);
        cs.beginText();
        cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
        cs.newLineAtOffset(100, 700);
        cs.showText("Password-protected test PDF");
        cs.endText();
        cs.close();

        AccessPermission accessPermission = new AccessPermission();
        StandardProtectionPolicy policy = new StandardProtectionPolicy(
                ownerPassword, userPassword, accessPermission);
        policy.setEncryptionKeyLength(128);
        doc.protect(policy);
        doc.save(protectedPdf);
        doc.close();
        return protectedPdf;
    }

}
