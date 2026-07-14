package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.PadesLevel;
import com.github.intoolswetrust.jsignpdf.pades.signing.ca.EmbeddedCa;
import com.github.intoolswetrust.jsignpdf.pades.signing.tsa.EmbeddedTsaServer;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PadesLevelReader;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

import eu.europa.esig.dss.enumerations.SignatureLevel;

/**
 * Tests the space reserved in the PDF for the CMS signature. DSS reserves a fixed number of bytes before the
 * document is digested, so the reservation has to be right up front: too small and signing dies with an opaque
 * "signature size is too small" error. A long certificate chain combined with an embedded timestamp is exactly
 * the case that overruns the DSS default, so the size is estimated from the chain, with a retry as a safety net.
 */
public class ContentSizeSigningTest extends SigningTestBase {

    /** The fixed reservation DSS falls back on when no content size is set — and the size that proved too small. */
    private static final int DSS_DEFAULT_CONTENT_SIZE = 9472;

    private static EmbeddedCa embeddedCa;
    private static EmbeddedTsaServer tsaServer;

    @BeforeAll
    public static void startServers() throws Exception {
        embeddedCa = new EmbeddedCa();
        embeddedCa.start();
        tsaServer = new EmbeddedTsaServer();
        tsaServer.start();
    }

    @AfterAll
    public static void stopServers() {
        if (embeddedCa != null) {
            embeddedCa.stop();
        }
        if (tsaServer != null) {
            tsaServer.stop();
        }
    }

    /** A deliberately tiny reservation must be grown by the retry rather than failing the signature. */
    @Test
    public void testUndersizedReservationRecoversViaRetry() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setContentSize(100);

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "The retry must grow the reservation and still produce a valid signature");
    }

    /** With the retry switched off, a too-small reservation must fail loudly instead of silently growing. */
    @Test
    public void testUndersizedReservationFailsWhenRetryDisabled() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setContentSize(100);
        options.setRetryOnUndersize(false);

        boolean result = new SignerLogic(options).signFile(inputFile, outputFile);

        assertFalse(result, "An undersized reservation must fail when the retry is disabled");
    }

    /** A generous explicit reservation must sign in a single pass. */
    @Test
    public void testExplicitContentSizeSigns() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setContentSize(32768);

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "An explicit, generous content size must produce a valid signature");
    }

    /**
     * The regression case: a long chain (signer under six intermediates, RSA-4096 signing key — about 8 kB of
     * certificates on its own) plus a timestamp overruns the fixed size DSS reserves by default. The first half
     * of this test pins that down — with the old fixed reservation and no retry, signing fails — and the second
     * half shows the estimate derived from the chain gets it right in one pass.
     */
    @Test
    public void testLongChainWithTimestampOverrunsDssDefaultButSignsWithEstimate() throws Exception {
        BasicConfig options = createCaSignedOptions(embeddedCa, 6, 4096);
        options.setPadesLevel(PadesLevel.BASELINE_T);
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        options.getTsaConfig().setTsaHashAlgorithm("SHA-256");

        options.setContentSize(DSS_DEFAULT_CONTENT_SIZE);
        options.setRetryOnUndersize(false);
        assertFalse(new SignerLogic(options).signFile(inputFile, outputFile),
                "Precondition: this chain does not fit in the size DSS reserves by default");

        // 0 = estimate the reservation from the certificate chain and the signing options. The retry stays off,
        // so this only passes if the estimate is right first time — with the retry on, a bad estimate would be
        // silently papered over and the test would prove nothing about the estimate itself.
        options.setContentSize(0);
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "The estimated reservation must fit the chain and the timestamp");
        assertTrue(result.hasTimestamp, "The timestamp must be embedded");
        assertEquals(SignatureLevel.PAdES_BASELINE_T, PadesLevelReader.readLevel(outputFile));
    }
}
