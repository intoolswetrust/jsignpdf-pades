package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.TestConstants.Keystore;
import com.github.intoolswetrust.jsignpdf.pades.TestConstants.TestPrivateKey;
import com.github.intoolswetrust.jsignpdf.pades.signing.ca.EmbeddedCa;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

/**
 * Abstract base class for signing integration tests. Creates a minimal PDF 1.7 document
 * using PDFBox, registers the BouncyCastle provider, and provides helper methods for
 * configuring {@link BasicConfig} and running sign-then-validate workflows.
 */
public abstract class SigningTestBase {

    /** Alias and passwords of the signing key the embedded CA issues for a test. */
    protected static final String CA_KEY_ALIAS = "signer";
    protected static final char[] CA_KEYSTORE_PASSWD = "storepass".toCharArray();
    protected static final char[] CA_KEY_PASSWD = "keypass".toCharArray();

    private static File unsignedPdf;

    @TempDir
    Path tempDir;

    protected File inputFile;
    protected File outputFile;

    /**
     * Registers the BouncyCastle provider and generates a minimal unsigned PDF 1.7 for use
     * as signing input across all tests.
     */
    @BeforeAll
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        unsignedPdf = File.createTempFile("unsigned-", ".pdf");
        unsignedPdf.deleteOnExit();
        PDDocument doc = new PDDocument();
        doc.setVersion(1.7f);
        PDPage page = new PDPage();
        doc.addPage(page);
        PDPageContentStream cs = new PDPageContentStream(doc, page);
        cs.beginText();
        cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
        cs.newLineAtOffset(100, 700);
        cs.showText("Test PDF for signing");
        cs.endText();
        cs.close();
        doc.save(unsignedPdf);
        doc.close();
    }

    /**
     * Copies the unsigned PDF into the per-test temp folder and returns configured signing options
     * for the given key and keystore.
     */
    protected BasicConfig createOptions(TestPrivateKey key, Keystore keystore) throws Exception {
        inputFile = new File(tempDir.toFile(), "input.pdf");
        Files.copy(unsignedPdf.toPath(), inputFile.toPath());
        outputFile = new File(tempDir.toFile(), "output.pdf");
        return key.toSignerOptions(keystore);
    }

    /** Creates signing options using the default key (RSA2048) and keystore (JKS). */
    protected BasicConfig createDefaultOptions() throws Exception {
        return createOptions(TestPrivateKey.RSA2048, Keystore.JKS);
    }

    /**
     * Copies the unsigned PDF into the per-test temp folder and returns signing options for a fresh key issued
     * by the given embedded CA. The key's certificate carries a CRL distribution point pointing at the CA's
     * loopback endpoint, so revocation data is reachable — the precondition for the LT/LTA levels.
     *
     * @param ca            the running embedded CA
     * @param intermediates how many intermediate CAs to interpose between the root and the signer
     * @param keySize       RSA key size of the signing key
     */
    protected BasicConfig createCaSignedOptions(EmbeddedCa ca, int intermediates, int keySize) throws Exception {
        inputFile = new File(tempDir.toFile(), "input.pdf");
        Files.copy(unsignedPdf.toPath(), inputFile.toPath());
        outputFile = new File(tempDir.toFile(), "output.pdf");

        KeyStore keystore = ca.issueSigningKeyStore(CA_KEY_ALIAS, CA_KEY_PASSWD, intermediates, keySize);
        File keystoreFile = new File(tempDir.toFile(), "ca-signer.jks");
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            keystore.store(fos, CA_KEYSTORE_PASSWD);
        }

        BasicConfig options = new BasicConfig();
        options.setKeyStoreType("JKS");
        options.setKeyStoreFile(keystoreFile);
        options.setKeyStorePassword(CA_KEYSTORE_PASSWD);
        options.setKeyAlias(CA_KEY_ALIAS);
        options.setKeyPassword(CA_KEY_PASSWD);
        return options;
    }

    /** Creates signing options for a key issued directly by the embedded CA root (RSA-2048, no intermediates). */
    protected BasicConfig createCaSignedOptions(EmbeddedCa ca) throws Exception {
        return createCaSignedOptions(ca, 0, EmbeddedCa.DEFAULT_KEY_SIZE);
    }

    /**
     * Writes a certificate into the per-test temp folder in DER form, so it can be handed to the trust
     * configuration as a trusted certificate file.
     */
    protected File writeCertificateFile(X509Certificate certificate, String fileName) throws Exception {
        File file = new File(tempDir.toFile(), fileName);
        Files.write(file.toPath(), certificate.getEncoded());
        return file;
    }

    /**
     * Signs a PDF using {@link SignerLogic}, asserts success, and returns the
     * {@link PdfSignatureValidator} validation result.
     */
    protected ValidationResult signAndValidate(BasicConfig options) throws Exception {
        boolean result = new SignerLogic(options).signFile(inputFile, outputFile);
        assertTrue(result, "Signing should succeed");
        assertTrue(outputFile.exists(), "Output file should exist");
        return PdfSignatureValidator.validate(outputFile);
    }

    protected File getUnsignedPdf() {
        return unsignedPdf;
    }
}
