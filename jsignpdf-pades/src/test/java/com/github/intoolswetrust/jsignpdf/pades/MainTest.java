package com.github.intoolswetrust.jsignpdf.pades;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.file.Path;
import java.security.Security;
import java.util.TreeSet;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.beust.jcommander.JCommander;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.Pkcs11Config;
import com.github.intoolswetrust.jsignpdf.pades.config.VisibleSignatureConfig;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MainTest {

    @TempDir
    Path tempDir;

    @BeforeAll
    static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testParseHelpFlag() {
        BasicConfig config = new BasicConfig();
        Pkcs11Config p11config = new Pkcs11Config();
        JCommander jcmd = JCommander.newBuilder().addObject(new Object[]{config, p11config}).build();
        jcmd.parse("--help");
        assertTrue(config.isPrintHelp());
    }

    @Test
    void testParseVersionFlag() {
        BasicConfig config = new BasicConfig();
        Pkcs11Config p11config = new Pkcs11Config();
        JCommander jcmd = JCommander.newBuilder().addObject(new Object[]{config, p11config}).build();
        jcmd.parse("--version");
        assertTrue(config.isPrintVersion());
    }

    @Test
    void testParseListKeystoreTypesFlag() {
        BasicConfig config = new BasicConfig();
        Pkcs11Config p11config = new Pkcs11Config();
        JCommander jcmd = JCommander.newBuilder().addObject(new Object[]{config, p11config}).build();
        jcmd.parse("-lkt");
        assertTrue(config.isListKeyStores());
    }

    @Test
    void testParseListKeysFlag() {
        BasicConfig config = new BasicConfig();
        Pkcs11Config p11config = new Pkcs11Config();
        JCommander jcmd = JCommander.newBuilder().addObject(new Object[]{config, p11config}).build();
        jcmd.parse("-lk", "-kst", "JKS", "-ksf", "src/test/resources/test-keystore.jks", "-ksp", "keystorepass");
        assertTrue(config.isListKeys());
    }

    @Test
    void testParseQuietFlag() {
        BasicConfig config = new BasicConfig();
        Pkcs11Config p11config = new Pkcs11Config();
        JCommander jcmd = JCommander.newBuilder().addObject(new Object[]{config, p11config}).build();
        jcmd.parse("-q");
        assertTrue(config.isQuiet());
    }

    @Test
    void testParseSigningArgs() {
        BasicConfig config = new BasicConfig();
        Pkcs11Config p11config = new Pkcs11Config();
        JCommander jcmd = JCommander.newBuilder().addObject(new Object[]{config, p11config}).build();
        jcmd.parse("-kst", "JKS", "-ksf", "keystore.jks", "-ksp", "pass", "-ka", "mykey",
                "-r", "Test reason", "-l", "Test location", "-c", "test@example.com",
                "--pades-level", "BASELINE_T",
                "file1.pdf", "file2.pdf");
        assertEquals("JKS", config.getKeyStoreType());
        assertArrayEquals("pass".toCharArray(), config.getKeyStorePassword());
        assertEquals("mykey", config.getKeyAlias());
        assertEquals("Test reason", config.getReason());
        assertEquals("Test location", config.getLocation());
        assertEquals("test@example.com", config.getContact());
        assertEquals(2, config.getFiles().size());
    }

    @Test
    void testParseVisibleSignatureArgs() {
        BasicConfig config = new BasicConfig();
        Pkcs11Config p11config = new Pkcs11Config();
        JCommander jcmd = JCommander.newBuilder().addObject(new Object[]{config, p11config}).build();
        jcmd.parse("-V", "-pg", "2", "-llx", "50.5", "-lly", "60", "-urx", "200", "-ury", "110",
                "--text", "Custom text", "-fs", "14.0", "dummy.pdf");
        VisibleSignatureConfig visConfig = config.getVisibleSignatureConfig();
        assertTrue(visConfig.isVisible());
        assertEquals(2, visConfig.getPage());
        assertEquals(50.5f, visConfig.getPositionLLX(), 0.01f);
        assertEquals(60f, visConfig.getPositionLLY(), 0.01f);
        assertEquals(200f, visConfig.getPositionURX(), 0.01f);
        assertEquals(110f, visConfig.getPositionURY(), 0.01f);
        assertEquals("Custom text", visConfig.getText());
        assertEquals(14.0f, visConfig.getTextFontSize(), 0.01f);
    }

    @Test
    void testParseEncryptionArgs() {
        BasicConfig config = new BasicConfig();
        Pkcs11Config p11config = new Pkcs11Config();
        JCommander jcmd = JCommander.newBuilder().addObject(new Object[]{config, p11config}).build();
        jcmd.parse("--encrypt-before-sign", "-opwd", "owner", "-upwd", "user", "dummy.pdf");
        assertTrue(config.isEncryptBeforeSign());
        assertArrayEquals("owner".toCharArray(), config.getPdfOwnerPwd());
        assertArrayEquals("user".toCharArray(), config.getPdfUserPwd());
    }

    @Test
    void testParseTsaArgs() {
        BasicConfig config = new BasicConfig();
        Pkcs11Config p11config = new Pkcs11Config();
        JCommander jcmd = JCommander.newBuilder().addObject(new Object[]{config, p11config}).build();
        jcmd.parse("-ts", "http://tsa.example.com", "-tsu", "user", "-tsp", "pass",
                "--tsa-policy-oid", "1.2.3", "--tsa-hash-algorithm", "SHA-256",
                "-ta", "PASSWORD", "dummy.pdf");
        assertEquals("http://tsa.example.com", config.getTsaConfig().getTsaServerUrl());
        assertEquals("user", config.getTsaConfig().getTsaUser());
        assertArrayEquals("pass".toCharArray(), config.getTsaConfig().getTsaPassword());
        assertEquals("1.2.3", config.getTsaConfig().getTsaPolicyOid());
        assertEquals("SHA-256", config.getTsaConfig().getTsaHashAlgorithm());
        assertEquals(com.github.intoolswetrust.jsignpdf.pades.types.ServerAuthentication.PASSWORD,
                config.getTsaConfig().getTsaServerAuthn());
    }

    @Test
    void testListKeystoreTypes() {
        TreeSet<String> types = new TreeSet<>(Security.getAlgorithms("KeyStore"));
        assertNotNull(types);
        assertTrue(types.contains("JKS"));
        assertTrue(types.contains("PKCS12"));
    }

    @Test
    void testEndToEndWithParsedConfig() throws Exception {
        File inPdf = new File(tempDir.toFile(), "input.pdf");
        try (PDDocument doc = new PDDocument()) {
            doc.setVersion(1.7f);
            PDPage page = new PDPage();
            doc.addPage(page);
            try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
                cs.beginText();
                cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                cs.newLineAtOffset(100, 700);
                cs.showText("CLI test");
                cs.endText();
            }
            doc.save(inPdf);
        }

        File outPdf = new File(tempDir.toFile(), "output.pdf");

        BasicConfig config = new BasicConfig();
        Pkcs11Config p11config = new Pkcs11Config();
        JCommander jcmd = JCommander.newBuilder().addObject(new Object[]{config, p11config}).build();
        jcmd.parse("-kst", "JKS",
                "-ksf", "src/test/resources/test-keystore.jks",
                "-ksp", "keystorepass",
                "-ka", "rsa2048",
                "-kp", "RSA2048pass",
                inPdf.getAbsolutePath());

        SignerLogic logic = new SignerLogic(config);
        boolean result = logic.signFile(inPdf, outPdf);
        assertTrue(result, "Signing should succeed");
        assertTrue(outPdf.exists(), "Output should exist");
        assertTrue(outPdf.length() > inPdf.length(), "Signed file should be larger");
    }
}
