package com.github.intoolswetrust.jsignpdf.pades.validator;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import com.beust.jcommander.JCommander;
import com.github.intoolswetrust.jsignpdf.pades.validator.config.OutputFormat;
import com.github.intoolswetrust.jsignpdf.pades.validator.config.ValidatorConfig;

public class MainTest {

    @Test
    void testParseHelpFlag() {
        ValidatorConfig config = new ValidatorConfig();
        JCommander.newBuilder().addObject(config).build().parse("--help");
        assertTrue(config.isHelp());
    }

    @Test
    void testParseQuietFlag() {
        ValidatorConfig config = new ValidatorConfig();
        JCommander.newBuilder().addObject(config).build().parse("-q");
        assertTrue(config.isQuiet());
    }

    @Test
    void testParseFormatText() {
        ValidatorConfig config = new ValidatorConfig();
        JCommander.newBuilder().addObject(config).build().parse("-f", "TEXT", "dummy.pdf");
        assertEquals(OutputFormat.TEXT, config.getFormat());
    }

    @Test
    void testParseFormatJson() {
        ValidatorConfig config = new ValidatorConfig();
        JCommander.newBuilder().addObject(config).build().parse("-f", "JSON", "dummy.pdf");
        assertEquals(OutputFormat.JSON, config.getFormat());
    }

    @Test
    void testParseFormatXml() {
        ValidatorConfig config = new ValidatorConfig();
        JCommander.newBuilder().addObject(config).build().parse("-f", "XML", "dummy.pdf");
        assertEquals(OutputFormat.XML, config.getFormat());
    }

    @Test
    void testParseFormatEtsi() {
        ValidatorConfig config = new ValidatorConfig();
        JCommander.newBuilder().addObject(config).build().parse("-f", "ETSI", "dummy.pdf");
        assertEquals(OutputFormat.ETSI, config.getFormat());
    }

    @Test
    void testParseSkipRevocation() {
        ValidatorConfig config = new ValidatorConfig();
        JCommander.newBuilder().addObject(config).build().parse("--skip-revocation", "dummy.pdf");
        assertTrue(config.isSkipRevocation());
    }

    @Test
    void testParseTrustOptions() {
        ValidatorConfig config = new ValidatorConfig();
        JCommander.newBuilder().addObject(config).build().parse(
                "--trust-use-default-lotl",
                "--trust-certificate-file", "/tmp/cert.pem",
                "dummy.pdf");
        assertTrue(config.getTrustConfig().isUseDefaultLotl());
        assertEquals(1, config.getTrustConfig().getCertificateFiles().size());
    }

    @Test
    void testParseVerbose() {
        ValidatorConfig config = new ValidatorConfig();
        JCommander.newBuilder().addObject(config).build().parse("--verbose", "dummy.pdf");
        assertTrue(config.isVerbose());
    }

    @Test
    void testDefaultValues() {
        ValidatorConfig config = new ValidatorConfig();
        JCommander.newBuilder().addObject(config).build().parse("file.pdf");
        assertFalse(config.isHelp());
        assertFalse(config.isQuiet());
        assertFalse(config.isVerbose());
        assertFalse(config.isSkipRevocation());
        assertEquals(OutputFormat.TEXT, config.getFormat());
        assertEquals(1, config.getFiles().size());
    }
}
