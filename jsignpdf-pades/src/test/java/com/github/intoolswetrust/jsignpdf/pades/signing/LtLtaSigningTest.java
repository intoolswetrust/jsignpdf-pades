package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.PadesLevel;
import com.github.intoolswetrust.jsignpdf.pades.signing.ca.EmbeddedCa;
import com.github.intoolswetrust.jsignpdf.pades.signing.tsa.EmbeddedTsaServer;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PadesLevelReader;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PadesLevelReader.TimestampDigest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;

/**
 * Tests the long-term PAdES levels. LT embeds the revocation data proving the signer was valid when it signed,
 * and LTA adds an archive timestamp on top. DSS only collects that data for a chain it can anchor, so both
 * levels need a trust source and network access — the whole point of the embedded CA (whose CRL is reachable on
 * a loopback port) and the embedded TSA (whose certificate is pinned as an anchor for the archive timestamp).
 */
public class LtLtaSigningTest extends SigningTestBase {

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

    @Test
    public void testLtWithTrustedChainAndReachableRevocation() throws Exception {
        BasicConfig options = trustedCaOptions(PadesLevel.BASELINE_LT);

        assertTrue(new SignerLogic(options).signFile(inputFile, outputFile), "LT signing should succeed");

        assertEquals(SignatureLevel.PAdES_BASELINE_LT, PadesLevelReader.readLevel(outputFile));
    }

    @Test
    public void testLtaWithTrustedChainAndReachableRevocation() throws Exception {
        BasicConfig options = trustedCaOptions(PadesLevel.BASELINE_LTA);

        assertTrue(new SignerLogic(options).signFile(inputFile, outputFile), "LTA signing should succeed");

        assertEquals(SignatureLevel.PAdES_BASELINE_LTA, PadesLevelReader.readLevel(outputFile));
    }

    /**
     * The requested TSA hash algorithm has to reach every timestamp. An LTA signature carries a signature
     * timestamp <em>and</em> an archive timestamp (which PAdES implements as a document timestamp, hence the
     * {@link TimestampType#DOCUMENT_TIMESTAMP}); setting the digest on only the former leaves the archive
     * timestamp on the DSS default — the requested algorithm silently half-applied.
     */
    @Test
    public void testTsaHashAlgorithmAppliesToTheArchiveTimestampToo() throws Exception {
        BasicConfig options = trustedCaOptions(PadesLevel.BASELINE_LTA);
        options.getTsaConfig().setTsaHashAlgorithm("SHA-512");

        assertTrue(new SignerLogic(options).signFile(inputFile, outputFile), "LTA signing should succeed");

        List<TimestampDigest> timestamps = PadesLevelReader.readTimestampDigests(outputFile);
        assertTrue(timestamps.stream().anyMatch(t -> t.type() == TimestampType.SIGNATURE_TIMESTAMP),
                "LTA must carry a signature timestamp");
        assertTrue(timestamps.stream().anyMatch(t -> t.type() == TimestampType.DOCUMENT_TIMESTAMP),
                "LTA must carry an archive (document) timestamp");
        for (TimestampDigest timestamp : timestamps) {
            assertEquals(DigestAlgorithm.SHA512, timestamp.digestAlgorithm(),
                    "The requested TSA hash algorithm must reach the " + timestamp.type());
        }
    }

    /** Revocation data cannot be fetched offline, so LT must refuse up front rather than emit a weaker level. */
    @Test
    public void testLtFailsWhenOffline() throws Exception {
        BasicConfig options = trustedCaOptions(PadesLevel.BASELINE_LT);
        options.setOnline(false);

        assertFalse(new SignerLogic(options).signFile(inputFile, outputFile), "LT must fail in offline mode");
        assertFalse(outputFile.exists(), "No output must be written");
    }

    /** DSS skips revocation fetching for a chain it cannot anchor, so LT without any trust source is hopeless. */
    @Test
    public void testLtFailsWithoutTrustSource() throws Exception {
        BasicConfig options = createCaSignedOptions(embeddedCa);
        options.setPadesLevel(PadesLevel.BASELINE_LT);
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        // No trust anchors configured.

        assertFalse(new SignerLogic(options).signFile(inputFile, outputFile),
                "LT must fail when no trust source is configured");
    }

    /**
     * The private-PKI escape hatch: with the trust and revocation alerts relaxed, DSS attaches the LT structure
     * it can even though nothing anchors the chain. The same options without the flag fail (see
     * {@link #testLtFailsWithoutTrustSource()}), which is what makes this a test of the flag and not of luck.
     */
    @Test
    public void testAllowUntrustedProducesLtForAnUnanchoredChain() throws Exception {
        BasicConfig options = createCaSignedOptions(embeddedCa);
        options.setPadesLevel(PadesLevel.BASELINE_LT);
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        options.setAllowUntrusted(true);

        assertTrue(new SignerLogic(options).signFile(inputFile, outputFile),
                "--trust-allow-untrusted must let LT through for an unanchored chain");
        assertTrue(outputFile.exists(), "Output file should exist");
    }

    /**
     * When DSS refuses the signature because a chain is not anchored, it names the offending certificates only
     * by a {@code C-<fingerprint>} token id. Here the TSA certificate is trusted but the signer's CA is not, so
     * DSS reaches the revocation step and rejects the signer chain — and the error has to name the signer
     * certificate and the CA to add, not leave the user staring at a fingerprint.
     */
    @Test
    public void testUntrustedSignerChainIsNamedInTheError() throws Exception {
        BasicConfig options = createCaSignedOptions(embeddedCa);
        options.setPadesLevel(PadesLevel.BASELINE_LT);
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        // The TSA is trusted, the signer's issuing CA deliberately is not.
        File tsaFile = writeCertificateFile(tsaServer.getCertificate(), "tsa-only.crt");
        options.getTrustConfig().setCertificateFiles(Collections.singletonList(tsaFile));

        CapturingLogHandler handler = new CapturingLogHandler();
        Logger logger = Logger.getLogger("com.github.intoolswetrust.jsignpdf.pades");
        logger.addHandler(handler);
        try {
            assertFalse(new SignerLogic(options).signFile(inputFile, outputFile),
                    "LT signing with an unanchored signer chain must fail");
        } finally {
            logger.removeHandler(handler);
        }

        String severe = handler.severeMessages();
        assertTrue(severe.contains("Signer chain certificate"), "The error must say which chain is at fault");
        assertTrue(severe.contains("JSignPdf Test Signer"), "The error must name the signer certificate");
        assertTrue(severe.contains("JSignPdf Test Root CA"), "The error must name the CA to trust");
    }

    /** Collects the SEVERE log records, so the engine's own diagnostics can be asserted on. */
    private static final class CapturingLogHandler extends Handler {
        private final StringBuilder severe = new StringBuilder();

        @Override
        public void publish(LogRecord record) {
            if (record.getLevel().intValue() >= Level.SEVERE.intValue()) {
                severe.append(new SimpleFormatter().formatMessage(record)).append('\n');
            }
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }

        String severeMessages() {
            return severe.toString();
        }
    }

    /**
     * Options signing with a CA-issued key at the requested level, through the embedded TSA, with the CA root
     * and the TSA certificate pinned as trust anchors. Trusting the issuer is what makes DSS fetch the signer's
     * revocation data at all; trusting the self-signed TSA certificate spares the archive timestamp's own chain
     * from needing revocation data of its own.
     */
    private BasicConfig trustedCaOptions(PadesLevel level) throws Exception {
        BasicConfig options = createCaSignedOptions(embeddedCa);
        options.setPadesLevel(level);
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        options.getTsaConfig().setTsaHashAlgorithm("SHA-256");

        File caFile = writeCertificateFile(embeddedCa.getCaCertificate(), "ca.crt");
        File tsaFile = writeCertificateFile(tsaServer.getCertificate(), "tsa.crt");
        options.getTrustConfig().setCertificateFiles(Arrays.asList(caFile, tsaFile));
        return options;
    }
}
