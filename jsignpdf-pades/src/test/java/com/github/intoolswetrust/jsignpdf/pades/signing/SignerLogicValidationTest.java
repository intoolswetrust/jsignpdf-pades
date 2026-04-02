package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.TestConstants.Keystore;
import com.github.intoolswetrust.jsignpdf.pades.TestConstants.TestPrivateKey;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;

/**
 * Tests for validation/error paths in {@link SignerLogic#signFile(File, File)}.
 */
public class SignerLogicValidationTest extends SigningTestBase {

    @Test
    public void testSignFileWithNullInFile() throws Exception {
        BasicConfig options = createDefaultOptions();
        boolean result = new SignerLogic(options).signFile(null, outputFile);
        assertFalse(result, "signFile should return false for null inFile");
    }

    @Test
    public void testSignFileWithNullOutFile() throws Exception {
        BasicConfig options = createDefaultOptions();
        boolean result = new SignerLogic(options).signFile(inputFile, null);
        assertFalse(result, "signFile should return false for null outFile");
    }

    @Test
    public void testSignFileWithNonExistentInput() throws Exception {
        BasicConfig options = createDefaultOptions();
        File nonExistent = new File(tempDir.toFile(), "does-not-exist.pdf");
        boolean result = new SignerLogic(options).signFile(nonExistent, outputFile);
        assertFalse(result, "signFile should return false for non-existent input file");
    }

    @Test
    public void testSignFileWithSameInAndOutPath() throws Exception {
        BasicConfig options = createDefaultOptions();
        boolean result = new SignerLogic(options).signFile(inputFile, inputFile);
        assertFalse(result, "signFile should return false when inFile == outFile");
    }

    @Test
    public void testSignFileWithDirectoryAsInput() throws Exception {
        BasicConfig options = createDefaultOptions();
        File directory = tempDir.toFile();
        boolean result = new SignerLogic(options).signFile(directory, outputFile);
        assertFalse(result, "signFile should return false when input is a directory");
    }

    @Test
    public void testSigningWithExpiredKeyFails() throws Exception {
        BasicConfig options = createOptions(TestPrivateKey.EXPIRED, Keystore.JKS);

        boolean result = new SignerLogic(options).signFile(inputFile, outputFile);

        assertFalse(result, "Signing with an expired certificate should fail");
    }

    @Test
    public void testSigningRandomBytesFails() throws Exception {
        BasicConfig options = createDefaultOptions();
        File corrupt = new File(tempDir.toFile(), "random.pdf");
        try (FileOutputStream fos = new FileOutputStream(corrupt)) {
            fos.write(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 });
        }

        boolean result = new SignerLogic(options).signFile(corrupt, outputFile);

        assertFalse(result, "Signing random bytes should fail");
    }

    @Test
    public void testSigningEmptyFileFails() throws Exception {
        BasicConfig options = createDefaultOptions();
        File empty = new File(tempDir.toFile(), "empty.pdf");
        empty.createNewFile();

        boolean result = new SignerLogic(options).signFile(empty, outputFile);

        assertFalse(result, "Signing an empty file should fail");
    }

    @Test
    public void testSigningTruncatedPdfFails() throws Exception {
        BasicConfig options = createDefaultOptions();
        // Create a file that starts with a PDF header but is truncated
        File truncated = new File(tempDir.toFile(), "truncated.pdf");
        try (FileOutputStream fos = new FileOutputStream(truncated)) {
            fos.write("%PDF-1.7\n".getBytes(StandardCharsets.US_ASCII));
        }

        boolean result = new SignerLogic(options).signFile(truncated, outputFile);

        assertFalse(result, "Signing a truncated PDF should fail");
    }

    @Test
    public void testSigningTextFileWithPdfExtensionFails() throws Exception {
        BasicConfig options = createDefaultOptions();
        File textFile = new File(tempDir.toFile(), "notapdf.pdf");
        try (FileOutputStream fos = new FileOutputStream(textFile)) {
            fos.write("This is not a PDF file.".getBytes(StandardCharsets.UTF_8));
        }

        boolean result = new SignerLogic(options).signFile(textFile, outputFile);

        assertFalse(result, "Signing a text file with .pdf extension should fail");
    }
}
