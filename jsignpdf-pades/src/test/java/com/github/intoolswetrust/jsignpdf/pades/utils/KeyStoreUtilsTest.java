package com.github.intoolswetrust.jsignpdf.pades.utils;

import static com.github.intoolswetrust.jsignpdf.pades.TestConstants.KEYSTORE_JKS;
import static com.github.intoolswetrust.jsignpdf.pades.TestConstants.KEYSTORE_PKCS12;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.SortedSet;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.KeyStoreUtils;
import com.github.intoolswetrust.jsignpdf.pades.TestConstants;

/**
 * JUnit tests for {@link KeyStoreUtils} class.
 *
 * @author Josef Cacek
 */
public class KeyStoreUtilsTest {

    /**
     * Tests {@link KeyStoreUtils#getKeyStores()}.
     */
    @Test
    public void testGetKeyStores() {
        final SortedSet<String> keyStores = KeyStoreUtils.getKeyStores();
        assertNotNull(keyStores);
        // basic types
        assertTrue(keyStores.contains(KEYSTORE_JKS));
        assertTrue(keyStores.contains(KEYSTORE_PKCS12));
    }

    /**
     * Tests {@link KeyStoreUtils#getKeyAliases(com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig)}
     */
    @Test
    public void testGetKeyAliases() throws Exception {
        for (TestConstants.Keystore keystore : TestConstants.Keystore.values()) {
            for (TestConstants.TestPrivateKey privateKey : TestConstants.TestPrivateKey.values()) {
                System.out.println("Testing " + keystore + ":" + privateKey);
                String[] keyAliases = KeyStoreUtils.getKeyAliases(privateKey.toSignerOptions(keystore));
                assertNotNull(keyAliases);
                assertTrue(keyAliases.length > 0);
                List<String> keyList = Arrays.asList(keyAliases);
                assertTrue(keyList.contains(privateKey.getAlias()) != privateKey.isExpired());
            }
        }
    }
}
