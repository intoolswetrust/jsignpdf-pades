package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.signing.tsa.EmbeddedTsaServer;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

/**
 * Tests that the TSA policy OID is correctly embedded in signed PDFs.
 */
public class TsaPolicyOidTest extends SigningTestBase {

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
    public void testTimestampPolicyOid() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        options.getTsaConfig().setTsaHashAlgorithm("SHA-256");
        options.getTsaConfig().setTsaPolicyOid("1.2.3.4.5");

        ValidationResult result = signAndValidate(options);

        assertTrue(result.hasTimestamp, "Signature should contain a timestamp token");
        assertEquals("1.2.3.4.5", result.timestampPolicyOid,
                "Timestamp policy OID should match the configured value");
    }

    @Test
    public void testTimestampWithoutExplicitPolicyOid() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        options.getTsaConfig().setTsaHashAlgorithm("SHA-256");

        ValidationResult result = signAndValidate(options);

        assertTrue(result.hasTimestamp, "Signature should contain a timestamp token");
        assertNotNull(result.timestampPolicyOid, "Timestamp policy OID should be present (from TSA server default)");
    }
}
