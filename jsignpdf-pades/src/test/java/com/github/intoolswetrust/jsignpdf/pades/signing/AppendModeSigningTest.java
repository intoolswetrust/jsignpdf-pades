package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;

/**
 * Tests PDF signing in append vs. non-append mode. Append mode preserves the original PDF
 * bytes and appends the signature, while non-append mode rewrites the entire file.
 */
public class AppendModeSigningTest extends SigningTestBase {


    /** Verifies that append mode preserves the original file bytes as a prefix of the output. */
    @Test
    public void testAppendPreservesOriginalBytes() throws Exception {
        BasicConfig options = createDefaultOptions();

        File inFile = new File(options.getInFile());
        byte[] originalBytes = Files.readAllBytes(inFile.toPath());

        boolean success = new SignerLogic(options).signFile();
        assertTrue(success, "Signing should succeed");

        File outFile = new File(options.getEffectiveOutFile());
        byte[] signedBytes = Files.readAllBytes(outFile.toPath());

        assertTrue(signedBytes.length > originalBytes.length, "Signed file should be larger than original");

        byte[] prefix = new byte[originalBytes.length];
        System.arraycopy(signedBytes, 0, prefix, 0, originalBytes.length);
        assertArrayEquals(originalBytes, prefix, "Signed file should start with original bytes");
    }
}
