package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.signing.tsa.EmbeddedTsaServer;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;
import com.github.intoolswetrust.jsignpdf.pades.types.ServerAuthentication;

/**
 * Integration tests for PDF signing with RFC 3161 timestamping. Uses an
 * embedded TSA server backed by BouncyCastle TSP.
 */
public class TimestampSigningTest extends SigningTestBase {

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

    private BasicConfig createTimestampOptions() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        options.getTsaConfig().setTsaHashAlgorithm("SHA-256");
        return options;
    }

    @Test
    public void testSigningWithTimestamp() throws Exception {
        BasicConfig options = createTimestampOptions();
        ValidationResult result = signAndValidate(options);

        assertEquals(1, result.signatureCount, "Should have 1 signature");
        assertTrue(result.signatureValid, "Signature should be valid");
        assertTrue(result.hasTimestamp, "Signature should contain a timestamp token");
    }

    @Test
    public void testTimestampDigestAlgorithm() throws Exception {
        BasicConfig options = createTimestampOptions();
        ValidationResult result = signAndValidate(options);

        assertTrue(result.hasTimestamp, "Should have timestamp");
        assertNotNull(result.timestampDigestAlgorithmOid, "Timestamp digest algorithm OID should be present");
        // We requested SHA-256; its OID is 2.16.840.1.101.3.4.2.1
        assertEquals("2.16.840.1.101.3.4.2.1", result.timestampDigestAlgorithmOid,
                "Timestamp digest algorithm should be SHA-256");
    }

    @Test
    public void testTimestampHasDate() throws Exception {
        BasicConfig options = createTimestampOptions();
        ValidationResult result = signAndValidate(options);

        assertTrue(result.hasTimestamp, "Should have timestamp");
        assertNotNull(result.timestampDate, "Timestamp date should be present");
    }

    @Test
    public void testTsaHashAlgorithmSha1() throws Exception {
        assertTsaHashAlgorithm("SHA-1", "1.3.14.3.2.26");
    }

    @Test
    public void testTsaHashAlgorithmSha384() throws Exception {
        assertTsaHashAlgorithm("SHA-384", "2.16.840.1.101.3.4.2.2");
    }

    @Test
    public void testTsaHashAlgorithmSha512() throws Exception {
        assertTsaHashAlgorithm("SHA-512", "2.16.840.1.101.3.4.2.3");
    }

    private void assertTsaHashAlgorithm(String tsaHashAlg, String expectedOid) throws Exception {
        BasicConfig options = createDefaultOptions();
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        options.getTsaConfig().setTsaHashAlgorithm(tsaHashAlg);

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertTrue(result.hasTimestamp, "Should have timestamp");
        assertEquals(expectedOid, result.timestampDigestAlgorithmOid,
                "Timestamp digest algorithm should be " + tsaHashAlg);
    }

    @Test
    public void testSigningWithTsaBasicAuthentication() throws Exception {
        EmbeddedTsaServer authTsa = new EmbeddedTsaServer();
        authTsa.requireBasicAuth("tsaUser", "tsaSecret");
        authTsa.start();
        try {
            BasicConfig options = createDefaultOptions();
            options.getTsaConfig().setTsaServerUrl(authTsa.getUrl());
            options.getTsaConfig().setTsaHashAlgorithm("SHA-256");
            options.getTsaConfig().setTsaServerAuthn(ServerAuthentication.PASSWORD);
            options.getTsaConfig().setTsaUser("tsaUser");
            options.getTsaConfig().setTsaPassword("tsaSecret".toCharArray());

            ValidationResult result = signAndValidate(options);

            assertEquals(1, result.signatureCount, "Should have 1 signature");
            assertTrue(result.signatureValid, "Signature should be valid");
            assertTrue(result.hasTimestamp, "Signature should contain a timestamp token");
        } finally {
            authTsa.stop();
        }
    }

    @Test
    public void testSigningWithTsaBasicAuthenticationWrongPassword() throws Exception {
        EmbeddedTsaServer authTsa = new EmbeddedTsaServer();
        authTsa.requireBasicAuth("tsaUser", "tsaSecret");
        authTsa.start();
        try {
            BasicConfig options = createDefaultOptions();
            options.getTsaConfig().setTsaServerUrl(authTsa.getUrl());
            options.getTsaConfig().setTsaHashAlgorithm("SHA-256");
            options.getTsaConfig().setTsaServerAuthn(ServerAuthentication.PASSWORD);
            options.getTsaConfig().setTsaUser("tsaUser");
            options.getTsaConfig().setTsaPassword("wrongPassword".toCharArray());

            boolean result = new SignerLogic(options).signFile(inputFile, outputFile);
            assertFalse(result, "Signing should fail when TSA authentication fails");
        } finally {
            authTsa.stop();
        }
    }

    @Test
    public void testSignatureWithoutTimestampHasNoToken() throws Exception {
        BasicConfig options = createDefaultOptions();
        // Timestamp NOT enabled
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        assertFalse(result.hasTimestamp, "Signature without TSA should have no timestamp token");
    }
}
