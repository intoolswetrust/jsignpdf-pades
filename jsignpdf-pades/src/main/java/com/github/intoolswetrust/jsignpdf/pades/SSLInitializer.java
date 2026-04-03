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

    private final HostnameVerifier origVerifier;
    private final SSLSocketFactory origSslSocketFactory;

    public SSLInitializer(BasicConfig config) throws NoSuchAlgorithmException, KeyManagementException,
            KeyStoreException, CertificateException, IOException, UnrecoverableKeyException {
        origVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
        origSslSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
        KeyManager[] km = null;
        TsaConfig tsaConfig = config.getTsaConfig();
        TrustManager[] trustManagers = new TrustManager[] { new DynamicX509TrustManager(config.isInsecureRelaxTls()) };

        if (config.isInsecureRelaxTls()) {
            LOGGER.warning("Relaxing TLS security.");

            // Details for the properties -
            // http://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/JSSERefGuide.html
            // Workaround for
            // http://sourceforge.net/tracker/?func=detail&atid=1037906&aid=3491269&group_id=216921
            System.setProperty("jsse.enableSNIExtension", "false");

            // just in case...
            System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");
            System.setProperty("sun.security.ssl.allowLegacyHelloMessages", "true");

            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
        }

        if (tsaConfig.getTsaServerAuthn() == ServerAuthentication.CERTIFICATE) {
            char[] pwd = null;
            if (StringUtils.isNotEmpty(tsaConfig.getTsaKeyStorePassword())) {
                pwd = tsaConfig.getTsaKeyStorePassword().toCharArray();
            }
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
    }
}
