package com.github.intoolswetrust.jsignpdf.pades.signing.ca;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

/**
 * Embedded mini-CA for the signing integration tests, the counterpart to
 * {@link com.github.intoolswetrust.jsignpdf.pades.signing.tsa.EmbeddedTsaServer}. It generates a self-signed
 * root CA on the fly and runs an in-JVM HTTP server on a random loopback port that serves the CRL of every CA
 * it creates (no external network). Signing certificates issued by {@link #issueSigningKeyStore} carry a CRL
 * distribution point pointing at that endpoint, so DSS can fetch revocation data for them and produce the
 * LT / LTA baseline levels offline and deterministically.
 *
 * <p>
 * Pin the root via {@link #getCaCertificate()} as a DSS trust anchor: DSS skips revocation fetching for
 * untrusted chains, so an LT/LTA test must trust the issuer before the CRL is even consulted.
 * </p>
 */
public class EmbeddedCa {

    private static final String SIG_ALG = "SHA256withRSA";

    private static final long DAY_MS = 24 * 60 * 60 * 1000L;

    /** Default RSA key size of an issued signing certificate. */
    public static final int DEFAULT_KEY_SIZE = 2048;

    private HttpServer httpServer;
    private String crlBaseUrl;

    /** Root at index 0, followed by the intermediates created on demand; the index is the CRL endpoint key. */
    private final List<Ca> cas = new ArrayList<>();
    private final AtomicLong crlNumber = new AtomicLong(1);
    private final AtomicLong serial = new AtomicLong(100);

    /**
     * Generates the self-signed root CA (with {@code keyCertSign + cRLSign} usage) and starts the loopback CRL
     * endpoint. Must be called before issuing certificates.
     */
    public void start() throws Exception {
        httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        httpServer.createContext("/crl", new CrlHandler());
        httpServer.start();
        crlBaseUrl = "http://127.0.0.1:" + httpServer.getAddress().getPort() + "/crl";

        cas.add(createRootCa());
    }

    /** Stops the CRL HTTP server. */
    public void stop() {
        if (httpServer != null) {
            httpServer.stop(0);
        }
    }

    /** Returns the self-signed root CA certificate, to be pinned as a DSS trust anchor. */
    public X509Certificate getCaCertificate() {
        return cas.get(0).certificate;
    }

    /**
     * Issues a fresh RSA-2048 signing certificate directly under the root CA and packages the private key plus
     * the {@code [signer, root]} chain into an in-memory JKS keystore.
     *
     * @param alias  the key entry alias
     * @param keyPwd the password protecting the key entry
     */
    public KeyStore issueSigningKeyStore(String alias, char[] keyPwd) throws Exception {
        return issueSigningKeyStore(alias, keyPwd, 0, DEFAULT_KEY_SIZE);
    }

    /**
     * Issues a signing certificate and packages it, with its full chain, into an in-memory JKS keystore. Every
     * certificate in the chain below the root carries a CRL distribution point pointing at this CA's loopback
     * endpoint, so DSS can collect revocation data for the whole chain.
     *
     * <p>
     * {@code intermediates} and {@code keySize} exist to grow the CMS: the number of encapsulated certificates
     * and the RSA key size are what push a signature past the {@code /Contents} DSS reserves for it, which is
     * the condition the content-size estimation has to cope with.
     * </p>
     *
     * @param alias         the key entry alias
     * @param keyPwd        the password protecting the key entry
     * @param intermediates how many intermediate CAs to interpose between the root and the signer
     * @param keySize       RSA key size of the signing key
     * @return a JKS keystore holding the signing key and its {@code [signer, intermediates..., root]} chain
     */
    public KeyStore issueSigningKeyStore(String alias, char[] keyPwd, int intermediates, int keySize)
            throws Exception {
        Ca issuer = cas.get(0);
        List<X509Certificate> chain = new ArrayList<>();
        for (int i = 0; i < intermediates; i++) {
            Ca intermediate = createIntermediateCa(issuer, "CN=JSignPdf Test Intermediate CA " + (i + 1)
                    + ", O=JSignPdf Test");
            chain.add(intermediate.certificate);
            issuer = intermediate;
        }

        KeyPair signerKeyPair = generateKeyPair(keySize);
        X500Name signerName = new X500Name("CN=JSignPdf Test Signer, O=JSignPdf Test");
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        X509v3CertificateBuilder builder = certificateBuilder(issuer, signerName, signerKeyPair);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(signerKeyPair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(issuer.certificate));
        builder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint(issuer));
        X509Certificate signerCertificate = sign(builder, issuer);

        // [signer, intermediates (leaf-most first), root]
        List<X509Certificate> fullChain = new ArrayList<>();
        fullChain.add(signerCertificate);
        for (int i = chain.size() - 1; i >= 0; i--) {
            fullChain.add(chain.get(i));
        }
        fullChain.add(cas.get(0).certificate);

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry(alias, signerKeyPair.getPrivate(), keyPwd, fullChain.toArray(new X509Certificate[0]));
        return ks;
    }

    private Ca createRootCa() throws Exception {
        KeyPair keyPair = generateKeyPair(DEFAULT_KEY_SIZE);
        X500Name name = new X500Name("CN=JSignPdf Test Root CA, O=JSignPdf Test");
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, nextSerial(), notBefore(),
                notAfter(), name, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

        ContentSigner signer = new JcaContentSignerBuilder(SIG_ALG).setProvider("BC").build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        return new Ca(0, name, keyPair, certificate);
    }

    private Ca createIntermediateCa(Ca issuer, String dn) throws Exception {
        KeyPair keyPair = generateKeyPair(DEFAULT_KEY_SIZE);
        X500Name name = new X500Name(dn);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        X509v3CertificateBuilder builder = certificateBuilder(issuer, name, keyPair);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(issuer.certificate));
        builder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint(issuer));

        Ca intermediate = new Ca(cas.size(), name, keyPair, sign(builder, issuer));
        cas.add(intermediate);
        return intermediate;
    }

    private X509v3CertificateBuilder certificateBuilder(Ca issuer, X500Name subject, KeyPair subjectKeyPair) {
        return new JcaX509v3CertificateBuilder(issuer.name, nextSerial(), notBefore(), notAfter(), subject,
                subjectKeyPair.getPublic());
    }

    private X509Certificate sign(X509v3CertificateBuilder builder, Ca issuer) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder(SIG_ALG).setProvider("BC")
                .build(issuer.keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private static KeyPair generateKeyPair(int keySize) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        return kpg.generateKeyPair();
    }

    private BigInteger nextSerial() {
        return BigInteger.valueOf(serial.getAndIncrement());
    }

    private static Date notBefore() {
        return new Date(System.currentTimeMillis() - DAY_MS);
    }

    private static Date notAfter() {
        return new Date(System.currentTimeMillis() + 365 * DAY_MS);
    }

    /** Builds the CRL distribution point extension pointing at the given CA's endpoint on the loopback server. */
    private CRLDistPoint crlDistPoint(Ca ca) {
        DistributionPointName dpn = new DistributionPointName(
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl(ca))));
        return new CRLDistPoint(new DistributionPoint[] { new DistributionPoint(dpn, null, null) });
    }

    private String crlUrl(Ca ca) {
        return crlBaseUrl + "?ca=" + ca.index;
    }

    /** Generates a DER-encoded CRL signed by the given CA, with an empty revoked list (every cert is "good"). */
    private byte[] generateCrl(Ca ca) throws Exception {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(ca.name, new Date(System.currentTimeMillis() - 60 * 60 * 1000L));
        builder.setNextUpdate(notAfter());
        builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(crlNumber.getAndIncrement())));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(ca.certificate));

        ContentSigner signer = new JcaContentSignerBuilder(SIG_ALG).setProvider("BC").build(ca.keyPair.getPrivate());
        X509CRLHolder holder = builder.build(signer);
        return holder.getEncoded();
    }

    /** Serves the CRL of the CA selected by the {@code ca=<index>} query parameter (defaulting to the root). */
    private class CrlHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }
                Ca ca = resolveCa(exchange.getRequestURI().getQuery());
                if (ca == null) {
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }
                byte[] crl = generateCrl(ca);
                exchange.getResponseHeaders().set("Content-Type", "application/pkix-crl");
                exchange.sendResponseHeaders(200, crl.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(crl);
                }
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            }
        }

        private Ca resolveCa(String query) {
            int index = 0;
            if (query != null && query.startsWith("ca=")) {
                try {
                    index = Integer.parseInt(query.substring(3));
                } catch (NumberFormatException e) {
                    return null;
                }
            }
            return index >= 0 && index < cas.size() ? cas.get(index) : null;
        }
    }

    /** One certificate authority: the root or an intermediate, each with its own CRL endpoint. */
    private static final class Ca {
        private final int index;
        private final X500Name name;
        private final KeyPair keyPair;
        private final X509Certificate certificate;

        Ca(int index, X500Name name, KeyPair keyPair, X509Certificate certificate) {
            this.index = index;
            this.name = name;
            this.keyPair = keyPair;
            this.certificate = certificate;
        }
    }
}
