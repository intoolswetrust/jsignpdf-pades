package com.github.intoolswetrust.jsignpdf.pades;

import static com.github.intoolswetrust.jsignpdf.pades.Constants.LOGGER;

import java.io.Closeable;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.commons.lang3.StringUtils;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.TsaConfig;
import com.github.intoolswetrust.jsignpdf.pades.types.ServerAuthentication;

/**
 * Helper class for handling default SSL connections settings (HTTPS).
 */
public class SSLInitializer  implements Closeable {

    private static final String PROP_SNI = "jsse.enableSNIExtension";
    private static final String PROP_UNSAFE_RENEG = "sun.security.ssl.allowUnsafeRenegotiation";
    private static final String PROP_LEGACY_HELLO = "sun.security.ssl.allowLegacyHelloMessages";

    private final HostnameVerifier origVerifier;
    private final SSLSocketFactory origSslSocketFactory;
    private final String origSni;
    private final String origUnsafeReneg;
    private final String origLegacyHello;

    public SSLInitializer(BasicConfig config) throws NoSuchAlgorithmException, KeyManagementException,
            KeyStoreException, CertificateException, IOException, UnrecoverableKeyException {
        origVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
        origSslSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
        KeyManager[] km = null;
        TsaConfig tsaConfig = config.getTsaConfig();
        TrustManager[] trustManagers = new TrustManager[] { new DynamicX509TrustManager(config.isInsecureRelaxTls()) };

        if (config.isInsecureRelaxTls()) {
            LOGGER.warning("Relaxing TLS security.");

            // Save original values (may be null if never set)
            origSni = System.getProperty(PROP_SNI);
            origUnsafeReneg = System.getProperty(PROP_UNSAFE_RENEG);
            origLegacyHello = System.getProperty(PROP_LEGACY_HELLO);

            // Details for the properties -
            // http://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/JSSERefGuide.html
            // Workaround for
            // http://sourceforge.net/tracker/?func=detail&atid=1037906&aid=3491269&group_id=216921
            System.setProperty(PROP_SNI, "false");

            // just in case...
            System.setProperty(PROP_UNSAFE_RENEG, "true");
            System.setProperty(PROP_LEGACY_HELLO, "true");

            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
        } else {
            origSni = null;
            origUnsafeReneg = null;
            origLegacyHello = null;
        }

        if (tsaConfig.getTsaServerAuthn() == ServerAuthentication.CERTIFICATE) {
            char[] pwd = tsaConfig.getTsaKeyStorePassword();
            LOGGER.info("Initializing KeyManager for TSA authentication");
            final String ksType = StringUtils.defaultIfBlank(tsaConfig.getTsaKeyStoreFileType(), KeyStore.getDefaultType());
            KeyStore keyStore = KeyStoreUtils.loadKeyStore(ksType, tsaConfig.getTsaKeyStoreFile(), pwd);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, pwd);
            km = keyManagerFactory.getKeyManagers();
        }
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(km, trustManagers, null);

        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    }

    @Override
    public void close() throws IOException {
        HttpsURLConnection.setDefaultHostnameVerifier(origVerifier);
        HttpsURLConnection.setDefaultSSLSocketFactory(origSslSocketFactory);
        restoreSystemProperty(PROP_SNI, origSni);
        restoreSystemProperty(PROP_UNSAFE_RENEG, origUnsafeReneg);
        restoreSystemProperty(PROP_LEGACY_HELLO, origLegacyHello);
    }

    private static void restoreSystemProperty(String key, String originalValue) {
        if (originalValue != null) {
            System.setProperty(key, originalValue);
        } else {
            System.clearProperty(key);
        }
    }
}
