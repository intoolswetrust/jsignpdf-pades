package com.github.intoolswetrust.jsignpdf.pades;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;

import java.io.File;

/**
 * Constants specific to JUnit tests.
 *
 * @author Josef Cacek
 */
public class TestConstants {

    public static final String KEYSTORE_JKS = "JKS";
    public static final String KEYSTORE_PKCS12 = "PKCS12";
    public static final String KEYSTORE_BCPKCS12 = "BCPKCS12";

    public static final char[] KEYSTORE_TEST_PASSWD = "keystorepass".toCharArray();
    public static final String KEYSTORE_FILE_JKS = "src/test/resources/test-keystore.jks";
    public static final String KEYSTORE_FILE_PKCS12 = "src/test/resources/test-keystore.p12";

    public static final String KEY_PASSWD_SUFFIX = "pass";

    public static enum Keystore {
        JKS(KEYSTORE_FILE_JKS), PKCS12(KEYSTORE_FILE_PKCS12),
        // BCPKCS12(KEYSTORE_FILE_PKCS12)
        ;

        private final String ksFile;

        private Keystore(final String aFilePath) {
            ksFile = aFilePath;
        }

        public String getKsFile() {
            return ksFile;
        }

        public String getKsType() {
            return name();
        }

        public char[] getPasswd() {
            return KEYSTORE_TEST_PASSWD;
        }
    }

    /**
     * Test private keys present in test keystore file.
     *
     * @author Josef Cacek
     */
    public static enum TestPrivateKey {
        EXPIRED(true), RSA1024(false), RSA2048(false), RSA4096(false), DSA1024(false);

        private final boolean expired;

        private TestPrivateKey(boolean anExpired) {
            expired = anExpired;
        }

        public boolean isExpired() {
            return expired;
        }

        public String getAlias() {
            return name().toLowerCase();
        }

        public char[] getPasswd() {
            return (name() + KEY_PASSWD_SUFFIX).toCharArray();
        }

        public BasicConfig toSignerOptions(final Keystore aKeystore) {
            final BasicConfig options = new BasicConfig();
            options.setKeyStoreType(aKeystore.getKsType());
            options.setKeyStoreFile(new File(aKeystore.getKsFile()));
            options.setKeyStorePassword(aKeystore.getPasswd());
            options.setKeyAlias(getAlias());
            options.setKeyPassword(getPasswd());
            return options;

        }
    }

}
