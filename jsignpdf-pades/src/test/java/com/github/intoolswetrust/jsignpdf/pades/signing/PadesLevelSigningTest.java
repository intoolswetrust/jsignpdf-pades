package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.PadesLevel;
import com.github.intoolswetrust.jsignpdf.pades.signing.tsa.EmbeddedTsaServer;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

/**
 * Tests for signing with different {@link PadesLevel} values.
 */
public class PadesLevelSigningTest extends SigningTestBase {

    private static EmbeddedTsaServer tsaServer;

    @BeforeAll
    public static void startTsa() throws Exception {
        tsaServer = new EmbeddedTsaServer();
        tsaServer.start();
    }

    @AfterAll
    public static void stopTsa() {
        if (tsaServer != null) {
            tsaServer.stop();
        }
    }

    @Test
    public void testBaselineBWithoutTsa() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setPadesLevel(PadesLevel.BASELINE_B);

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "BASELINE_B signature should be valid");
        assertFalse(result.hasTimestamp, "BASELINE_B without TSA should have no timestamp");
    }

    @Test
    public void testBaselineBWithTsaUpgradesToT() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setPadesLevel(PadesLevel.BASELINE_B);
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        options.getTsaConfig().setTsaHashAlgorithm("SHA-256");

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertTrue(result.hasTimestamp, "BASELINE_B with TSA should be auto-upgraded to T and have a timestamp");
    }

    @Test
    public void testBaselineTWithTsa() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setPadesLevel(PadesLevel.BASELINE_T);
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        options.getTsaConfig().setTsaHashAlgorithm("SHA-256");

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "BASELINE_T signature should be valid");
        assertTrue(result.hasTimestamp, "BASELINE_T should have a timestamp");
    }

    @Test
    public void testBaselineTWithoutTsaFails() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setPadesLevel(PadesLevel.BASELINE_T);
        // No TSA configured

        boolean result = new SignerLogic(options).signFile(inputFile, outputFile);

        assertFalse(result, "BASELINE_T without TSA should fail");
    }

    @Test
    public void testBaselineLtWithTsaButNoTrustFails() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setPadesLevel(PadesLevel.BASELINE_LT);
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        options.getTsaConfig().setTsaHashAlgorithm("SHA-256");
        // No trust sources configured

        boolean result = new SignerLogic(options).signFile(inputFile, outputFile);

        assertFalse(result, "BASELINE_LT without trust sources should fail");
    }

    @Test
    public void testBaselineLtaWithTsaButNoTrustFails() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setPadesLevel(PadesLevel.BASELINE_LTA);
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        options.getTsaConfig().setTsaHashAlgorithm("SHA-256");
        // No trust sources configured

        boolean result = new SignerLogic(options).signFile(inputFile, outputFile);

        assertFalse(result, "BASELINE_LTA without trust sources should fail");
    }
}
