package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;

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
}
