package com.github.intoolswetrust.jsignpdf.pades;

import static com.github.intoolswetrust.jsignpdf.pades.Constants.LOGGER;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;
import java.util.logging.Level;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * TrustManager which works with in-memory copy of cacerts truststore. If {@link Constants#RELAX_SSL_SECURITY} is true then it
 * adds missing server certificates to the truststore.
 */
public class DynamicX509TrustManager implements X509TrustManager {

    private final KeyStore trustStore;
    private final TrustManagerFactory trustManagerFactory;
    private final boolean insecureRelaxSsl;

    private volatile X509TrustManager trustManager;

    public DynamicX509TrustManager(boolean insecureRelaxSsl) {
        this.insecureRelaxSsl = insecureRelaxSsl;
        try {
            this.trustStore = KeyStoreUtils.createTrustStore();
            trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            reloadTrustStore();
        } catch (Exception e) {
            throw new RuntimeException("Unable to create TrustManager.", e);
        }
    }

    /**
     * Checks client's cert-chain - no extra step here.
     * 
     * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
     */
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        trustManager.checkClientTrusted(chain, authType);
    }

    /**
     * Checks server's cert-chain. If check fails and insecureRelaxSsl is true then the first certificate
     * from the chain is added to the truststore and the check is repeated.
     * 
     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String)
     */
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (insecureRelaxSsl) {
            try {
                trustManager.checkServerTrusted(chain, authType);
            } catch (CertificateException cx) {
                try {
                    X509Certificate cert = chain[0];
                    LOGGER.warning("Auto-trusting certificate: subject=\""
                            + cert.getSubjectX500Principal() + "\", SHA-256="
                            + fingerprintSha256(cert));
                    trustStore.setCertificateEntry(UUID.randomUUID().toString(), cert);
                    reloadTrustStore();
                } catch (Exception e) {
                    throw new CertificateException("Unable to recreate TrustManager", e);
                }
                trustManager.checkServerTrusted(chain, authType);
            }
        } else {
            trustManager.checkServerTrusted(chain, authType);
        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        return trustManager.getAcceptedIssuers();
    }

    /**
     * Reloads the in-memory trustore.
     */
    private void reloadTrustStore() throws KeyStoreException, NoSuchAlgorithmException {
        trustManagerFactory.init(trustStore);
        // acquire X509 trust manager from factory
        TrustManager tms[] = trustManagerFactory.getTrustManagers();
        for (int i = 0; i < tms.length; i++) {
            if (tms[i] instanceof X509TrustManager x509Tm) {
                trustManager = x509Tm;
                return;
            }
        }

        throw new NoSuchAlgorithmException("No X509TrustManager in TrustManagerFactory");
    }

    private static String fingerprintSha256(X509Certificate cert) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder(digest.length * 3 - 1);
            for (int i = 0; i < digest.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02X", digest[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Unable to compute certificate fingerprint", e);
            return "<unavailable>";
        }
    }

}
