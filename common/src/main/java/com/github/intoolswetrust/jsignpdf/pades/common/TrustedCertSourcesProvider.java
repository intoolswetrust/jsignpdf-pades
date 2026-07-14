package com.github.intoolswetrust.jsignpdf.pades.common;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;

/**
 * Builds the trusted certificate sources DSS resolves trust anchors from, out of a {@link TrustConfig}.
 */
public class TrustedCertSourcesProvider {

    private static final Logger LOGGER = Logger.getLogger(TrustedCertSourcesProvider.class.getPackage().getName());

    /** Canonical EU List of Trusted Lists location. */
    public static final String DEFAULT_EU_LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

    /**
     * Default Official Journal scheme-information URL announcing the certificates allowed to sign the EU LOTL.
     * Must stay in sync with the bundled OJ keystore ({@link #OJ_KEYSTORE_RESOURCE}); both were rotated by
     * OJ C/2026/1944 (April 2026). Override with {@code --trust-oj-url} when pointing at a newer OJ notice.
     */
    public static final String DEFAULT_OJ_URL = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=OJ:C_202601944";

    /** Classpath location of the bundled OJ keystore (it validates the LOTL's own signature). */
    static final String OJ_KEYSTORE_RESOURCE = "/com/github/intoolswetrust/jsignpdf/pades/common/eu-oj-keystore.p12";

    /** Keystore type / password of the bundled OJ keystore (matches the DSS demonstrations keystore). */
    private static final String OJ_KEYSTORE_TYPE = "PKCS12";
    private static final char[] OJ_KEYSTORE_PASSWORD = "dss-password".toCharArray();

    /** Pseudo store name for the JVM's default CA truststore (a file, not a {@link KeyStore} provider type). */
    private static final String CACERTS_STORE = "cacerts";

    /** Password of the JVM {@code cacerts} store when {@code javax.net.ssl.trustStorePassword} is unset. */
    private static final String CACERTS_DEFAULT_PASSWORD = "changeit";

    /** Name of the directory holding the cached trusted lists. */
    private static final String TL_CACHE_DIR_NAME = "dss-tl-cache";

    /**
     * How long a cached trusted-list / LOTL download stays fresh before DSS re-fetches it (24h). Trusted lists
     * change infrequently, so this lets repeat / batch signing reuse the on-disk cache instead of downloading
     * the whole LOTL again on every run.
     */
    private static final long TL_CACHE_EXPIRATION_MS = 24L * 60 * 60 * 1000;

    private final TrustConfig trustConfig;

    private final ProxyConfig proxyConfig;

    public TrustedCertSourcesProvider(TrustConfig trustConfig) {
        this(trustConfig, null);
    }

    /**
     * @param proxyConfig the HTTP proxy to download the trusted lists through, or {@code null} for a direct
     *                    connection
     */
    public TrustedCertSourcesProvider(TrustConfig trustConfig, ProxyConfig proxyConfig) {
        this.trustConfig = trustConfig;
        this.proxyConfig = proxyConfig;
    }

    /**
     * Builds the configured trusted certificate sources.
     *
     * @throws Exception if a configured source cannot be loaded (unreadable truststore or certificate,
     *                   unreachable LOTL, ...). Callers fail rather than continue with trust material that is
     *                   not the material the user asked for.
     */
    public CertificateSource[] createTrustedCertSources() throws Exception {
        List<CertificateSource> trustedSources = new ArrayList<>();
        LOTLSource[] lotlSources = getLotlSources();
        if (lotlSources.length > 0) {
            TLValidationJob tlValidationJob = new TLValidationJob();
            CommonsDataLoader dataLoader = new CommonsDataLoader();
            dataLoader.setProxyConfig(proxyConfig);
            FileCacheDataLoader onlineDataLoader = new FileCacheDataLoader(dataLoader);
            onlineDataLoader.setFileCacheDirectory(tlCacheDirectory());
            onlineDataLoader.setCacheExpirationTime(TL_CACHE_EXPIRATION_MS);
            tlValidationJob.setOnlineDataLoader(onlineDataLoader);
            tlValidationJob.setListOfTrustedListSources(lotlSources);
            TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
            tlValidationJob.setTrustedListCertificateSource(trustedListsCertificateSource);
            try {
                tlValidationJob.onlineRefresh();
            } catch (Exception e) {
                // Surface an actionable cause instead of an opaque DSS stack trace. Common causes: offline or
                // behind a proxy, or an OJ keystore too old to validate the LOTL signature any more.
                throw new IllegalStateException("Failed to refresh the trusted lists (check the network, or"
                        + " update the OJ keystore with --trust-oj-keystore-file)", e);
            }
            logTrustAnchorSummary(trustedListsCertificateSource);
            trustedSources.add(trustedListsCertificateSource);
        }

        for (File certFile : trustConfig.getCertificateFiles()) {
            CommonTrustedCertificateSource source = new CommonTrustedCertificateSource();
            source.addCertificate(DSSUtils.loadCertificate(certFile));
            trustedSources.add(source);
        }
        for (String certUrl : trustConfig.getCertificateUrls()) {
            CommonTrustedCertificateSource source = new CommonTrustedCertificateSource();
            try (InputStream is = new URL(certUrl).openStream()) {
                source.addCertificate(DSSUtils.loadCertificate(is));
            }
            trustedSources.add(source);
        }
        File truststoreFile = trustConfig.getKeystoreFile();
        if (truststoreFile != null) {
            KeyStoreCertificateSource source = new KeyStoreCertificateSource(truststoreFile,
                    trustConfig.getKeystoreType(), trustConfig.getKeystorePassword());
            trustedSources.add(asTrusted(source));
        }

        if (trustConfig.isUseSystemStore()) {
            for (String store : systemStoreNames()) {
                CertificateSource source = loadSystemStore(store);
                if (source != null) {
                    trustedSources.add(source);
                }
            }
        }
        return trustedSources.toArray(new CertificateSource[trustedSources.size()]);
    }

    /**
     * The OS / JVM certificate stores to take anchors from: the portable {@code cacerts} everywhere, plus the
     * machine root store on Windows and the login keychain on macOS.
     *
     * <p>
     * Only <em>root / CA</em> stores belong here. The Windows personal store {@code Windows-MY} is deliberately
     * left out: it holds the user's own end-entity certificates, and loading the signer's own certificate as a
     * trust anchor makes DSS reject the signature during LT/LTA self-validation ("Signing-certificate token was
     * not found!"). The signer's chain stays anchored through its issuing CA in {@code Windows-ROOT}.
     * </p>
     */
    private static List<String> systemStoreNames() {
        List<String> stores = new ArrayList<>();
        stores.add(CACERTS_STORE);
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            stores.add("Windows-ROOT");
        } else if (os.contains("mac")) {
            stores.add("KeychainStore");
        }
        return stores;
    }

    /**
     * Best-effort load of one OS / JVM certificate store. {@code cacerts} resolves the JVM's default CA
     * truststore (honouring the {@code javax.net.ssl.trustStore*} system properties); any other name is a
     * {@link KeyStore} type loaded from its provider. A store that cannot be opened is logged and skipped rather
     * than aborting the run.
     *
     * @return the loaded source, or {@code null} when the store could not be opened
     */
    private static CertificateSource loadSystemStore(String store) {
        try {
            KeyStoreCertificateSource source;
            if (CACERTS_STORE.equalsIgnoreCase(store)) {
                String type = System.getProperty("javax.net.ssl.trustStoreType", KeyStore.getDefaultType());
                String pwd = System.getProperty("javax.net.ssl.trustStorePassword", CACERTS_DEFAULT_PASSWORD);
                source = new KeyStoreCertificateSource(cacertsFile(), type, pwd.toCharArray());
            } else {
                source = new KeyStoreCertificateSource(store, (char[]) null);
            }
            LOGGER.info("Loaded " + source.getNumberOfCertificates() + " trust anchor(s) from the system"
                    + " certificate store '" + store + "'");
            return asTrusted(source);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not load the system certificate store '" + store + "' (skipped)", e);
            return null;
        }
    }

    /**
     * Resolves the JVM's default CA truststore file the way JSSE does: an explicit
     * {@code javax.net.ssl.trustStore} (unless {@code NONE}), else {@code $JAVA_HOME/lib/security/jssecacerts}
     * when it exists, else {@code $JAVA_HOME/lib/security/cacerts}.
     */
    private static File cacertsFile() {
        String override = System.getProperty("javax.net.ssl.trustStore");
        if (override != null && !override.isEmpty() && !"NONE".equals(override)) {
            return new File(override);
        }
        Path securityDir = Path.of(System.getProperty("java.home"), "lib", "security");
        File jssecacerts = securityDir.resolve("jssecacerts").toFile();
        return jssecacerts.exists() ? jssecacerts : securityDir.resolve("cacerts").toFile();
    }

    private LOTLSource[] getLotlSources() throws Exception {
        List<LOTLSource> lotlSources = new ArrayList<>();
        CertificateSource ojCertificateSource = null;

        if (trustConfig.isUseDefaultLotl()) {
            ojCertificateSource = ojKeystoreCertificateSource();
            lotlSources.add(europeanLotlSource(ojCertificateSource));
        }

        List<String> customLotlUrls = trustConfig.getLotlUrls();
        if (!customLotlUrls.isEmpty() && ojCertificateSource == null) {
            ojCertificateSource = ojKeystoreCertificateSource();
        }
        for (String url : customLotlUrls) {
            // "Bring your own trust": signed by the (bundled or overridden) OJ certificates and with pivot
            // support, but without the OJ announcement predicate, since a custom LOTL need not announce the EU
            // Official Journal URL. MRA support is opt-in, as only third-country mutual-recognition LOTLs need it.
            LOTLSource lotlSource = new LOTLSource();
            lotlSource.setUrl(url);
            lotlSource.setCertificateSource(ojCertificateSource);
            lotlSource.setPivotSupport(true);
            lotlSource.setMraSupport(trustConfig.isLotlMraSupport());
            lotlSources.add(lotlSource);
        }
        return lotlSources.toArray(new LOTLSource[lotlSources.size()]);
    }

    /**
     * Builds the European LOTL source, wired so DSS can validate the LOTL's own signature against the OJ
     * keystore and follow the pivot chain to the current trust anchors.
     */
    private LOTLSource europeanLotlSource(CertificateSource ojCertificateSource) {
        LOTLSource lotl = new LOTLSource();
        lotl.setUrl(defaultIfEmpty(trustConfig.getEuLotlUrl(), DEFAULT_EU_LOTL_URL));
        lotl.setCertificateSource(ojCertificateSource);
        lotl.setSigningCertificatesAnnouncementPredicate(
                new OfficialJournalSchemeInformationURI(defaultIfEmpty(trustConfig.getOjUrl(), DEFAULT_OJ_URL)));
        lotl.setPivotSupport(true);
        return lotl;
    }

    /**
     * Loads the certificate source that validates the LOTL signature: an external keystore when one is
     * configured, otherwise the keystore bundled on the classpath. Unlike the truststore, these certificates are
     * not trust anchors for document signers — they only tell DSS whether to accept the LOTL itself.
     */
    private CertificateSource ojKeystoreCertificateSource() throws Exception {
        File overrideFile = trustConfig.getOjKeystoreFile();
        if (overrideFile != null) {
            return new KeyStoreCertificateSource(overrideFile, KeyStore.getDefaultType(),
                    trustConfig.getOjKeystorePassword());
        }
        try (InputStream is = TrustedCertSourcesProvider.class.getResourceAsStream(OJ_KEYSTORE_RESOURCE)) {
            if (is == null) {
                throw new IllegalStateException("Bundled OJ keystore not found on the classpath: "
                        + OJ_KEYSTORE_RESOURCE);
            }
            return new KeyStoreCertificateSource(is, OJ_KEYSTORE_TYPE, OJ_KEYSTORE_PASSWORD);
        }
    }

    /**
     * Wraps a {@link KeyStoreCertificateSource} (whose source type is {@code OTHER}) in a
     * {@link CommonTrustedCertificateSource} so it qualifies as a {@code TRUSTED_STORE}. DSS's
     * {@code CommonCertificateVerifier.setTrustedCertSources} accepts only {@code TRUSTED_STORE} and
     * {@code TRUSTED_LIST} sources, so a raw keystore source confers no trust at all.
     */
    private static CertificateSource asTrusted(KeyStoreCertificateSource source) {
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.importAsTrusted(source);
        return trusted;
    }

    /**
     * Logs how many trust anchors the trusted lists produced, and how many lists were processed. Without this, a
     * LOTL that downloads but yields zero anchors (a national list that failed to sync, network filtering) looks
     * exactly like one whose anchors loaded fine but simply do not include the signer's CA — both surface later
     * only as an opaque "untrusted certificate chain" failure.
     */
    private static void logTrustAnchorSummary(TrustedListsCertificateSource source) {
        int anchors = source.getNumberOfCertificates();
        TLValidationJobSummary summary = source.getSummary();
        int tls = summary != null ? summary.getNumberOfProcessedTLs() : 0;
        int lotls = summary != null ? summary.getNumberOfProcessedLOTLs() : 0;
        String message = "Loaded " + anchors + " trust anchor(s) from " + tls + " trusted list(s) and " + lotls
                + " list(s) of trusted lists.";
        if (anchors == 0) {
            LOGGER.warning(message + " Without trust anchors no certificate chain can be trusted.");
        } else {
            LOGGER.info(message);
        }
    }

    /**
     * Resolves the directory DSS caches the downloaded trusted lists in. A stable location (rather than
     * {@link FileCacheDataLoader}'s default) lets the cache survive across runs, so repeat and batch signing do
     * not re-download the whole LOTL every time.
     */
    private static File tlCacheDirectory() {
        String userHome = System.getProperty("user.home");
        File cacheDir = userHome != null
                ? Path.of(userHome, ".jsignpdf-pades", TL_CACHE_DIR_NAME).toFile()
                : new File(System.getProperty("java.io.tmpdir"), "jsignpdf-pades-" + TL_CACHE_DIR_NAME);
        try {
            Files.createDirectories(cacheDir.toPath());
        } catch (Exception e) {
            // Not fatal: DSS recreates the directory on demand.
            LOGGER.log(Level.WARNING, "Could not create the trusted list cache directory " + cacheDir, e);
        }
        return cacheDir;
    }

    private static String defaultIfEmpty(String value, String fallback) {
        return value == null || value.isEmpty() ? fallback : value;
    }
}
