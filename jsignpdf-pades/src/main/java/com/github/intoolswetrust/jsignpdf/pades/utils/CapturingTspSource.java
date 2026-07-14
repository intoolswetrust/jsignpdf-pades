package com.github.intoolswetrust.jsignpdf.pades.utils;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;

import com.github.intoolswetrust.jsignpdf.pades.Constants;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

/**
 * A {@link TSPSource} decorator that records the certificate chain embedded in every timestamp token it hands
 * back, and logs the TSA exchange at FINE level. The recorded certificates let
 * {@link UntrustedChainReporter} name the <em>timestamp</em> chain — not just the signer chain — when DSS
 * refuses an LT/LTA signature because a chain is not anchored. Without them a failure caused by the timestamp
 * CA looks identical to one caused by the signer's CA.
 *
 * <p>
 * Capture is best-effort and never affects signing: the delegate's token is returned unchanged, and a token
 * that cannot be parsed for diagnostics is simply left unnamed in any later report.
 * </p>
 */
public class CapturingTspSource implements TSPSource {

    private static final long serialVersionUID = 1L;

    private final String tsaUrl;

    private final TSPSource delegate;

    /** Captured timestamp certificates, keyed by DSS token id to de-duplicate across the issued tokens. */
    private final Map<String, X509Certificate> capturedCerts = new LinkedHashMap<>();

    public CapturingTspSource(String tsaUrl, TSPSource delegate) {
        this.tsaUrl = tsaUrl;
        this.delegate = delegate;
    }

    @Override
    public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) throws DSSException {
        long startNanos = System.nanoTime();
        TimestampBinary token = delegate.getTimeStampResponse(digestAlgorithm, digest);
        long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L;
        capture(token);
        if (Constants.LOGGER.isLoggable(Level.FINE)) {
            logResponse(token, digestAlgorithm, elapsedMs);
        }
        return token;
    }

    private void logResponse(TimestampBinary token, DigestAlgorithm digestAlgorithm, long elapsedMs) {
        if (token == null) {
            Constants.LOGGER.fine("TSA " + tsaUrl + " (" + digestAlgorithm + "): empty response, elapsed="
                    + elapsedMs + "ms");
            return;
        }
        String genTime = "unparseable";
        int certs = 0;
        try {
            TimestampToken parsed = new TimestampToken(token.getBytes(), TimestampType.SIGNATURE_TIMESTAMP);
            genTime = String.valueOf(parsed.getGenerationTime());
            certs = parsed.getCertificates().size();
        } catch (Exception e) {
            // Diagnostics only.
        }
        Constants.LOGGER.fine("TSA " + tsaUrl + " (" + digestAlgorithm + "): " + token.getBytes().length
                + " bytes, genTime=" + genTime + ", certs=" + certs + ", elapsed=" + elapsedMs + "ms");
    }

    private void capture(TimestampBinary token) {
        if (token == null) {
            return;
        }
        try {
            TimestampToken parsed = new TimestampToken(token.getBytes(), TimestampType.SIGNATURE_TIMESTAMP);
            for (CertificateToken certToken : parsed.getCertificates()) {
                if (certToken != null && certToken.getCertificate() != null) {
                    capturedCerts.putIfAbsent(certToken.getDSSIdAsString(), certToken.getCertificate());
                }
            }
        } catch (Exception e) {
            // Diagnostics only: an unparseable token must never interfere with the signing operation itself.
        }
    }

    /** Returns the certificates seen in the issued timestamp tokens (the TSA certificate and any bundled CAs). */
    public Collection<X509Certificate> getCapturedCertificates() {
        return capturedCerts.values();
    }
}
