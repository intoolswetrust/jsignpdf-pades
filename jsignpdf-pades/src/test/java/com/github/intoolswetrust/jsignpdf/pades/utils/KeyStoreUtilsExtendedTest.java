package com.github.intoolswetrust.jsignpdf.pades.utils;

import static com.github.intoolswetrust.jsignpdf.pades.TestConstants.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.security.KeyStore;

import org.junit.jupiter.api.Test;

import com.beust.jcommander.JCommander;
import com.github.intoolswetrust.jsignpdf.pades.KeyStoreUtils;
import com.github.intoolswetrust.jsignpdf.pades.TestConstants.Keystore;
import com.github.intoolswetrust.jsignpdf.pades.TestConstants.TestPrivateKey;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;

import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;

/**
 * Extended tests for {@link KeyStoreUtils} methods not covered by {@link KeyStoreUtilsTest}.
 */
public class KeyStoreUtilsExtendedTest {

    @Test
    public void testGetCertAliasesFromKeyStore() throws Exception {
        KeyStore ks = KeyStoreUtils.loadKeyStore(KEYSTORE_JKS, new File(KEYSTORE_FILE_JKS), KEYSTORE_TEST_PASSWD);
        String[] certAliases = KeyStoreUtils.getCertAliases(ks);
        assertNotNull(certAliases);
        // test keystore has key entries, not standalone cert entries
    }

    @Test
    public void testGetCertAliasesNull() {
        String[] certAliases = KeyStoreUtils.getCertAliases(null);
        assertNull(certAliases);
    }

    @Test
    public void testLoadKeyStoreNullTypeNullFile() throws Exception {
        KeyStore ks = KeyStoreUtils.loadKeyStore(null, null, (char[]) null);
        assertNotNull(ks);
    }

    @Test
    public void testLoadKeyStoreExplicitPkcs12() throws Exception {
        KeyStore ks = KeyStoreUtils.loadKeyStore(KEYSTORE_PKCS12, new File(KEYSTORE_FILE_PKCS12), KEYSTORE_TEST_PASSWD);
        assertNotNull(ks);
        assertTrue(ks.aliases().hasMoreElements());
    }

    @Test
    public void testLoadKeyStoreWrongPassword() {
        assertThrows(Exception.class, () ->
                KeyStoreUtils.loadKeyStore(KEYSTORE_JKS, new File(KEYSTORE_FILE_JKS), "wrongpassword".toCharArray()));
    }

    @Test
    public void testGetOrDefaultKeyStoreTypeNull() {
        String type = KeyStoreUtils.getOrDefaultKeyStoreType(null);
        assertEquals(KeyStore.getDefaultType(), type);
    }

    @Test
    public void testGetOrDefaultKeyStoreTypeEmpty() {
        String type = KeyStoreUtils.getOrDefaultKeyStoreType("");
        assertEquals(KeyStore.getDefaultType(), type);
    }

    @Test
    public void testGetOrDefaultKeyStoreTypeExplicit() {
        String type = KeyStoreUtils.getOrDefaultKeyStoreType("JKS");
        assertEquals("JKS", type);
    }

    @Test
    public void testCreateKeyStoreSignatureTokenConnection() throws Exception {
        BasicConfig config = TestPrivateKey.RSA2048.toSignerOptions(Keystore.JKS);
        try (KeyStoreSignatureTokenConnection conn = KeyStoreUtils.createKeyStoreSignatureTokenConnection(config)) {
            assertNotNull(conn);
            // getKeys() uses keystore password to access private keys; use getKey() with explicit key password
            DSSPrivateKeyEntry key = conn.getKey(TestPrivateKey.RSA2048.getAlias(),
                    new java.security.KeyStore.PasswordProtection(TestPrivateKey.RSA2048.getPasswd()));
            assertNotNull(key);
            assertNotNull(key.getCertificate());
        }
    }

    @Test
    public void testGetKeyAliasesAllChecksDisabled() throws Exception {
        BasicConfig config = new BasicConfig();
        JCommander.newBuilder().addObject(config).build()
                .parse("--disable-validity-check", "--disable-key-usage-check", "--disable-critical-extensions-check");
        config.setKeyStoreType(Keystore.JKS.getKsType());
        config.setKeyStoreFile(new File(Keystore.JKS.getKsFile()));
        config.setKeyStorePassword(Keystore.JKS.getPasswd());

        String[] aliases = KeyStoreUtils.getKeyAliases(config);
        assertNotNull(aliases);
        // with all checks disabled, expired cert alias should be included
        boolean containsExpired = false;
        for (String alias : aliases) {
            if (alias.equals(TestPrivateKey.EXPIRED.getAlias())) {
                containsExpired = true;
                break;
            }
        }
        assertTrue(containsExpired, "Expired alias should be present when validity check is disabled");
    }
}
