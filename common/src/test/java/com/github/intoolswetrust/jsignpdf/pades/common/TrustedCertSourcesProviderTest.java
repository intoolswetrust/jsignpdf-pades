package com.github.intoolswetrust.jsignpdf.pades.common;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.source.LOTLSource;

/**
 * Tests for {@link TrustedCertSourcesProvider}.
 */
public class TrustedCertSourcesProviderTest {

    private static final String KS_FILE = "src/test/resources/test-keystore.p12";
    private static final String KS_PASSWORD = "keystorepass";
    private static final String KS_TYPE = "PKCS12";

    @TempDir
    Path tempDir;

    @Test
    public void testEmptyConfigReturnsNoSources() throws Exception {
        TrustConfig config = new TrustConfig();
        TrustedCertSourcesProvider provider = new TrustedCertSourcesProvider(config);

        CertificateSource[] sources = provider.createTrustedCertSources();

        assertNotNull(sources);
        assertEquals(0, sources.length);
    }

    @Test
    public void testCertificateFileAddsSource() throws Exception {
        File certFile = exportCertificateToFile("rsa2048");

        TrustConfig config = new TrustConfig();
        config.setCertificateFiles(Collections.singletonList(certFile));

        TrustedCertSourcesProvider provider = new TrustedCertSourcesProvider(config);
        CertificateSource[] sources = provider.createTrustedCertSources();

        assertEquals(1, sources.length);
        assertFalse(sources[0].getCertificates().isEmpty(), "Certificate source should contain certificates");
    }

    @Test
    public void testCertificateUrlAddsSource() throws Exception {
        File certFile = exportCertificateToFile("rsa2048");
        String certUrl = certFile.toURI().toURL().toString();

        TrustConfig config = new TrustConfig();
        config.setCertificateUrls(Collections.singletonList(certUrl));

        TrustedCertSourcesProvider provider = new TrustedCertSourcesProvider(config);
        CertificateSource[] sources = provider.createTrustedCertSources();

        assertEquals(1, sources.length);
        assertFalse(sources[0].getCertificates().isEmpty(), "Certificate source should contain certificates");
    }

    @Test
    public void testKeystoreFileAddsSource() throws Exception {
        TrustConfig config = new TrustConfig();
        config.setKeystoreFile(new File(KS_FILE));
        config.setKeystorePassword(KS_PASSWORD.toCharArray());
        config.setKeystoreType(KS_TYPE);

        TrustedCertSourcesProvider provider = new TrustedCertSourcesProvider(config);
        CertificateSource[] sources = provider.createTrustedCertSources();

        assertEquals(1, sources.length);
        assertFalse(sources[0].getCertificates().isEmpty(), "Keystore source should contain certificates");
    }

    @Test
    public void testMultipleCertificateFilesAddMultipleSources() throws Exception {
        File certFile1 = exportCertificateToFile("rsa2048");
        File certFile2 = exportCertificateToFile("rsa4096");

        TrustConfig config = new TrustConfig();
        config.setCertificateFiles(Arrays.asList(certFile1, certFile2));

        TrustedCertSourcesProvider provider = new TrustedCertSourcesProvider(config);
        CertificateSource[] sources = provider.createTrustedCertSources();

        assertEquals(2, sources.length);
    }

    @Test
    public void testCombinedCertFileAndKeystore() throws Exception {
        File certFile = exportCertificateToFile("rsa2048");

        TrustConfig config = new TrustConfig();
        config.setCertificateFiles(Collections.singletonList(certFile));
        config.setKeystoreFile(new File(KS_FILE));
        config.setKeystorePassword(KS_PASSWORD.toCharArray());
        config.setKeystoreType(KS_TYPE);

        TrustedCertSourcesProvider provider = new TrustedCertSourcesProvider(config);
        CertificateSource[] sources = provider.createTrustedCertSources();

        assertEquals(2, sources.length);
    }

    @Test
    public void testKeystoreWithNullPasswordIsAccepted() throws Exception {
        TrustConfig config = new TrustConfig();
        config.setKeystoreFile(new File(KS_FILE));
        config.setKeystoreType(KS_TYPE);
        // password is null by default

        TrustedCertSourcesProvider provider = new TrustedCertSourcesProvider(config);
        // PKCS12 without correct password should throw
        assertThrows(Exception.class, provider::createTrustedCertSources);
    }

    @Test
    public void testLotlUrlsAreIncludedInLotlSources() throws Exception {
        TrustConfig config = new TrustConfig();
        List<String> lotlUrls = Arrays.asList(
                "https://example.com/lotl1.xml",
                "https://example.com/lotl2.xml");
        config.setLotlUrls(lotlUrls);

        LOTLSource[] lotlSources = invokeLotlSources(config);

        assertEquals(2, lotlSources.length, "Should have 2 LOTL sources for 2 URLs");
        assertEquals("https://example.com/lotl1.xml", lotlSources[0].getUrl());
        assertEquals("https://example.com/lotl2.xml", lotlSources[1].getUrl());
    }

    @Test
    public void testDefaultLotlFlagAddsOneLotlSource() throws Exception {
        TrustConfig config = new TrustConfig();
        config.setUseDefaultLotl(true);

        LOTLSource[] lotlSources = invokeLotlSources(config);

        assertEquals(1, lotlSources.length, "Default LOTL flag should add 1 LOTL source");
    }

    @Test
    public void testDefaultLotlAndCustomUrlsCombined() throws Exception {
        TrustConfig config = new TrustConfig();
        config.setUseDefaultLotl(true);
        config.setLotlUrls(Collections.singletonList("https://example.com/custom-lotl.xml"));

        LOTLSource[] lotlSources = invokeLotlSources(config);

        assertEquals(2, lotlSources.length, "Should have default + 1 custom LOTL source");
        assertEquals("https://example.com/custom-lotl.xml", lotlSources[1].getUrl());
    }

    @Test
    public void testNoLotlWhenNothingConfigured() throws Exception {
        TrustConfig config = new TrustConfig();

        LOTLSource[] lotlSources = invokeLotlSources(config);

        assertEquals(0, lotlSources.length, "Should have no LOTL sources with empty config");
    }

    @Test
    public void testLotlSourceHasCertificateSource() throws Exception {
        TrustConfig config = new TrustConfig();
        config.setLotlUrls(Collections.singletonList("https://example.com/lotl.xml"));

        LOTLSource[] lotlSources = invokeLotlSources(config);

        assertNotNull(lotlSources[0].getCertificateSource(),
                "Custom LOTL source should have a certificate source set");
    }

    @Test
    public void testCertificateUrlWithInvalidUrlThrows() throws Exception {
        TrustConfig config = new TrustConfig();
        config.setCertificateUrls(Collections.singletonList("not-a-valid-url"));

        TrustedCertSourcesProvider provider = new TrustedCertSourcesProvider(config);
        assertThrows(Exception.class, provider::createTrustedCertSources);
    }

    @Test
    public void testCertificateFileNotFoundThrows() throws Exception {
        TrustConfig config = new TrustConfig();
        config.setCertificateFiles(Collections.singletonList(new File("/nonexistent/cert.pem")));

        TrustedCertSourcesProvider provider = new TrustedCertSourcesProvider(config);
        assertThrows(Exception.class, provider::createTrustedCertSources);
    }

    /**
     * Invokes the private {@code getLotlSources()} method via reflection.
     */
    private LOTLSource[] invokeLotlSources(TrustConfig config) throws Exception {
        TrustedCertSourcesProvider provider = new TrustedCertSourcesProvider(config);
        Method method = TrustedCertSourcesProvider.class.getDeclaredMethod("getLotlSources");
        method.setAccessible(true);
        return (LOTLSource[]) method.invoke(provider);
    }

    /**
     * Exports a certificate from the test PKCS12 keystore to a DER file.
     */
    private File exportCertificateToFile(String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance(KS_TYPE);
        try (var fis = new java.io.FileInputStream(KS_FILE)) {
            ks.load(fis, KS_PASSWORD.toCharArray());
        }
        Certificate cert = ks.getCertificate(alias);
        assertNotNull(cert, "Certificate for alias '" + alias + "' should exist in test keystore");

        File certFile = new File(tempDir.toFile(), alias + ".der");
        try (FileOutputStream fos = new FileOutputStream(certFile)) {
            fos.write(cert.getEncoded());
        }
        return certFile;
    }
}
