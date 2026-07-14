package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.PadesLevel;
import com.github.intoolswetrust.jsignpdf.pades.signing.ca.EmbeddedCa;
import com.github.intoolswetrust.jsignpdf.pades.signing.tsa.EmbeddedTsaServer;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PadesLevelReader;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

import eu.europa.esig.dss.enumerations.SignatureLevel;

/**
 * Exercises the test harness the LT / LTA and content-size work depends on: the {@link EmbeddedCa} (a mini-CA
 * whose issued certificates point at a reachable loopback CRL endpoint), the {@link EmbeddedTsaServer}, and
 * {@link PadesLevelReader} (which reads back the baseline level a signed PDF actually achieved).
 *
 * <p>
 * The LT/LTA happy paths themselves are not here yet: {@code SignerLogic} still builds a bare certificate
 * verifier with no trust anchors and no revocation sources, so DSS cannot collect the material those levels
 * embed. What this class pins down is that everything those tests will stand on — a trusted-by-pinning issuer,
 * a fetchable CRL, a working TSA, and an assertion that can tell B from T from LT — works today.
 * </p>
 */
public class SigningHarnessTest extends SigningTestBase {

    private static EmbeddedCa embeddedCa;
    private static EmbeddedTsaServer tsaServer;

    @BeforeAll
    public static void startServers() throws Exception {
        // BouncyCastle is registered by SigningTestBase.setUpClass(), which JUnit runs first (superclass
        // @BeforeAll before subclass @BeforeAll); the CA and TSA generate their key material through it.
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
    public void caIssuedKeySignsAtBaselineB() throws Exception {
        BasicConfig options = createCaSignedOptions(embeddedCa);
        options.setPadesLevel(PadesLevel.BASELINE_B);

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "A CA-issued key must produce a valid signature");
        assertEquals("CN=JSignPdf Test Signer,O=JSignPdf Test", result.signerCertificateSubject);
        assertEquals(SignatureLevel.PAdES_BASELINE_B, PadesLevelReader.readLevel(outputFile));
    }

    @Test
    public void timestampedSignatureReadsBackAsBaselineT() throws Exception {
        BasicConfig options = createCaSignedOptions(embeddedCa);
        options.setPadesLevel(PadesLevel.BASELINE_T);
        options.getTsaConfig().setTsaServerUrl(tsaServer.getUrl());
        options.getTsaConfig().setTsaHashAlgorithm("SHA-256");

        ValidationResult result = signAndValidate(options);

        assertTrue(result.hasTimestamp, "A TSA-signed PDF must carry a timestamp");
        // The level reader is what distinguishes the baselines: they all share the ETSI.CAdES.detached
        // subfilter, so only DSS's own view of the embedded material tells T apart from B.
        assertEquals(SignatureLevel.PAdES_BASELINE_T, PadesLevelReader.readLevel(outputFile));
    }

    @Test
    public void issuedChainCanIncludeIntermediatesAndLargerKeys() throws Exception {
        // Chain length and key size are what grow the CMS beyond the /Contents DSS reserves by default,
        // so the harness has to be able to produce a signer that is deliberately large.
        BasicConfig options = createCaSignedOptions(embeddedCa, 2, 4096);

        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "A signer under two intermediates must produce a valid signature");
        assertEquals(SignatureLevel.PAdES_BASELINE_B, PadesLevelReader.readLevel(outputFile));
    }

    @Test
    public void issuedChainIsRootedAtTheCa() throws Exception {
        KeyStore keystore = embeddedCa.issueSigningKeyStore(CA_KEY_ALIAS, CA_KEY_PASSWD, 2,
                EmbeddedCa.DEFAULT_KEY_SIZE);
        java.security.cert.Certificate[] chain = keystore.getCertificateChain(CA_KEY_ALIAS);

        assertEquals(4, chain.length, "signer + 2 intermediates + root");
        assertEquals(embeddedCa.getCaCertificate(), chain[chain.length - 1], "the chain must end at the root");
        // Each certificate must verify under the next one up, i.e. the chain is ordered leaf-first.
        for (int i = 0; i < chain.length - 1; i++) {
            chain[i].verify(chain[i + 1].getPublicKey());
        }
    }

    @Test
    public void signerCertificateCrlIsFetchableAndSignedByItsIssuer() throws Exception {
        KeyStore keystore = embeddedCa.issueSigningKeyStore(CA_KEY_ALIAS, CA_KEY_PASSWD);
        X509Certificate signer = (X509Certificate) keystore.getCertificateChain(CA_KEY_ALIAS)[0];

        String crlUrl = crlDistributionPointOf(signer);
        assertNotNull(crlUrl, "The issued certificate must carry a CRL distribution point");

        final X509CRL crl;
        try (InputStream is = new URL(crlUrl).openStream()) {
            crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(is);
        }
        // DSS fetches exactly this CRL to prove the signer is not revoked; if it is unreachable, unparseable
        // or not signed by the issuer, the LT/LTA levels cannot be reached.
        crl.verify(embeddedCa.getCaCertificate().getPublicKey());
        assertEquals(embeddedCa.getCaCertificate().getSubjectX500Principal(), crl.getIssuerX500Principal());
        assertTrue(crl.getRevokedCertificates() == null || crl.getRevokedCertificates().isEmpty(),
                "The issued signer must be listed as good");
    }

    @Test
    public void tsaCertificateIsExposedForTrustPinning() throws Exception {
        X509Certificate tsaCertificate = tsaServer.getCertificate();

        assertNotNull(tsaCertificate, "The TSA certificate is the trust anchor LTA needs for its archive"
                + " timestamp");
        assertTrue(tsaCertificate.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.8"),
                "The TSA certificate must carry the id-kp-timeStamping extended key usage");
        // The trust configuration takes anchors as DER certificate files, so writing it out has to work.
        assertTrue(writeCertificateFile(tsaCertificate, "tsa.crt").length() > 0);
    }

    /** Extracts the first HTTP CRL distribution point URL from a certificate, or null if it has none. */
    private static String crlDistributionPointOf(X509Certificate certificate) throws Exception {
        byte[] extensionValue = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (extensionValue == null) {
            return null;
        }
        byte[] octets = ASN1OctetString.getInstance(extensionValue).getOctets();
        CRLDistPoint distPoint = CRLDistPoint.getInstance(ASN1Primitive.fromByteArray(octets));
        for (DistributionPoint point : distPoint.getDistributionPoints()) {
            DistributionPointName name = point.getDistributionPoint();
            if (name == null || name.getType() != DistributionPointName.FULL_NAME) {
                continue;
            }
            for (GeneralName generalName : GeneralNames.getInstance(name.getName()).getNames()) {
                if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    return generalName.getName().toString();
                }
            }
        }
        return null;
    }
}
