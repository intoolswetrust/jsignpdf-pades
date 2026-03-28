package com.github.intoolswetrust.jsignpdf.pades.config;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import com.beust.jcommander.converters.FileConverter;

import com.github.intoolswetrust.jsignpdf.pades.Constants;
import com.github.intoolswetrust.jsignpdf.pades.types.CertificationLevel;
import com.github.intoolswetrust.jsignpdf.pades.types.HashAlgorithm;
import com.github.intoolswetrust.jsignpdf.pades.types.PDFEncryption;
import com.github.intoolswetrust.jsignpdf.pades.types.PrintRight;
import com.github.intoolswetrust.jsignpdf.pades.types.ServerAuthentication;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import org.apache.commons.lang3.StringUtils;

public class BasicConfig {

    @Parameter(converter = FileConverter.class, description = "PDF files to be signed")
    private List<File> files = new ArrayList<>();

    @Parameter(names = { "--help", "-h" }, help = true, description = "Prints this help")
    private boolean printHelp;

    @Parameter(names = { "--version", "-v" }, description = "Shows the application version")
    private boolean printVersion;

    @Parameter(names = { "--quiet", "-q" }, description = "Quiet mode - disable logging")
    private boolean quiet;

    @Parameter(names = { "--list-keystore-types", "-lkt" }, description = "Command listing available keystore types")
    private boolean listKeyStores;

    @Parameter(names = { "--list-keys", "-lk" }, description = "Command listing signing key aliases in the specified keystore")
    private boolean listKeys;

    @Parameter(names = { "--keystore-type", "-kst" }, description = "Keystore type to be loaded")
    private String keyStoreType;

    @Parameter(names = { "--keystore-file", "-ksf" }, description = "Keystore file to be used")
    private File keyStoreFile;

    @Parameter(names = { "--keystore-password", "-ksp" }, description = "KeyStore password")
    private String keyStorePassword;

    @Parameter(names = { "--key-password", "-kp" }, description = "Key password")
    private String keyPassword;

    @Parameter(names = { "--key-alias", "-ka" }, description = "Key alias to be used for signing")
    private String keyAlias;

    @Parameter(names = { "--pades-level", "-pl" }, description = "PAdES level")
    private PadesLevel padesLevel = PadesLevel.BASELINE_B;

    @Parameter(names = { "--out-suffix", "-os" }, description = "Signed file suffix to be attached to the original name")
    private String outSuffix = "_signed";

    @Parameter(names = { "--out-directory",
            "-d" }, description = "Directory to write the signed PDFs to. If not provided, the source directory of input PDF file is used.")
    private File outDirectory;

    @Parameter(names = { "--out-prefix", "-op" }, description = "Prefix for signed filename")
    private String outPrefix;

    @Parameter(names = "--out-path", description = "Output directory path for signed documents")
    private String outPath;

    @Parameter(names = "--disable-validity-check", description = "Don't check certificate validity in the keystore")
    private boolean disableValidityCheck;

    @Parameter(names = "--disable-key-usage-check", description = "Don't check certificate key-usage field in the keystore")
    private boolean disableKeyUsageCheck;

    @Parameter(names = "--disable-critical-extensions-check", description = "Don't check if all certificate critical extensions are known")
    private boolean disableCriticalExtensionsCheck;

    @Parameter(names = { "--digest-algorithm", "-da" }, description = "Digest algorithm used in the signature")
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

    // Signature Metadata
    @Parameter(names = { "--reason", "-r" }, description = "Reason for signature")
    private String reason;

    @Parameter(names = { "--location", "-l" }, description = "Location of signature")
    private String location;

    @Parameter(names = { "--contact", "-c" }, description = "Contact info")
    private String contact;

    @Parameter(names = { "--signer-name", "-sn" }, description = "Signer name")
    private String signerName;

    // Visible Signature
    @Parameter(names = { "--visible-signature", "-V" }, description = "Enable visible signature")
    private boolean visible;

    @Parameter(names = { "-pg", "--page" }, description = "Page for visible signature")
    private int page = 1;

    @Parameter(names = "-llx", description = "Lower left X coordinate of visible signature")
    private float positionLLX = 0;

    @Parameter(names = "-lly", description = "Lower left Y coordinate of visible signature")
    private float positionLLY = 0;

    @Parameter(names = "-urx", description = "Upper right X coordinate of visible signature")
    private float positionURX = 100;

    @Parameter(names = "-ury", description = "Upper right Y coordinate of visible signature")
    private float positionURY = 100;

    @Parameter(names = "--l2-text", description = "L2 text content for visible signature")
    private String l2Text;

    @Parameter(names = { "-fs", "--font-size" }, description = "Font size for visible signature text")
    private float l2TextFontSize = 10.0f;

    @Parameter(names = "--bg-path", description = "Background image path for visible signature")
    private String bgImgPath;

    // Encryption
    @Parameter(names = { "--encryption", "-pe" }, description = "Encryption mode (NONE, PASSWORD)")
    private String pdfEncryptionCli;
    private PDFEncryption pdfEncryption;

    @Parameter(names = { "--owner-password", "-opwd" }, description = "Owner password for encrypted PDF")
    private String pdfOwnerPwdCli;
    private char[] pdfOwnerPwd;

    @Parameter(names = { "--user-password", "-upwd" }, description = "User password for encrypted PDF")
    private String pdfUserPwdCli;
    private char[] pdfUserPwd;

    @Parameter(names = { "--print-right", "-pr" }, description = "Printing rights for encrypted PDF")
    private String rightPrintCli;
    private PrintRight rightPrinting;

    @Parameter(names = "--disable-copy", description = "Deny copy in encrypted documents")
    private boolean disableCopy;

    @Parameter(names = "--disable-assembly", description = "Deny assembly in encrypted documents")
    private boolean disableAssembly;

    @Parameter(names = "--disable-fill", description = "Deny fill in encrypted documents")
    private boolean disableFill;

    @Parameter(names = "--disable-screen-readers", description = "Deny screen readers in encrypted documents")
    private boolean disableScreenReaders;

    @Parameter(names = "--disable-modify-annotations", description = "Deny modify annotations in encrypted documents")
    private boolean disableModifyAnnotations;

    @Parameter(names = "--disable-modify-content", description = "Deny modify content in encrypted documents")
    private boolean disableModifyContent;

    private boolean rightCopy = true;
    private boolean rightAssembly = true;
    private boolean rightFillIn = true;
    private boolean rightScreanReaders = true;
    private boolean rightModifyAnnotations = true;
    private boolean rightModifyContents = true;

    // Hash and Certification
    @Parameter(names = { "--hash-algorithm", "-ha" }, description = "Hash algorithm (SHA1, SHA256, SHA384, SHA512, RIPEMD160)")
    private String hashAlgorithmCli;
    private HashAlgorithm hashAlgorithm;

    @Parameter(names = { "--certification-level", "-cl" }, description = "Certification level")
    private String certLevelCli;
    private CertificationLevel certLevel;

    // TSA enhancements
    @Parameter(names = { "--tsa-authentication", "-ta" }, description = "TSA auth method (NONE, PASSWORD, CERTIFICATE)")
    private String tsaAuthnCli;
    private ServerAuthentication tsaServerAuthn;

    @Parameter(names = { "--tsa-hash-algorithm", "-tsh" }, description = "TSA hash algorithm")
    private String tsaHashAlg;

    // Programmatic-only fields (not CLI)
    private String inFile;
    private String outFile;

    private boolean timestamp;

    @ParametersDelegate
    private final TsaConfig tsaConfig = new TsaConfig();

    @ParametersDelegate
    private final TrustConfig trustConfig = new TrustConfig();

    // ---- postParseCmdLine ----

    public void postParseCmdLine() {
        if (quiet) {
            Constants.LOGGER.setLevel(Level.OFF);
        }

        // Password conversions
        if (pdfOwnerPwdCli != null)
            setPdfOwnerPwd(pdfOwnerPwdCli);
        if (pdfUserPwdCli != null)
            setPdfUserPwd(pdfUserPwdCli);

        // Enum conversions
        if (certLevelCli != null)
            setCertLevel(certLevelCli);
        if (hashAlgorithmCli != null)
            setHashAlgorithm(hashAlgorithmCli);
        if (pdfEncryptionCli != null)
            setPdfEncryption(pdfEncryptionCli);
        if (rightPrintCli != null)
            setRightPrinting(rightPrintCli);
        if (tsaAuthnCli != null)
            setTsaServerAuthn(tsaAuthnCli);

        // Rights (disable flags invert to right flags)
        setRightCopy(!disableCopy);
        setRightAssembly(!disableAssembly);
        setRightFillIn(!disableFill);
        setRightScreanReaders(!disableScreenReaders);
        setRightModifyAnnotations(!disableModifyAnnotations);
        setRightModifyContents(!disableModifyContent);

        // TSA
        String tsaUrl = tsaConfig.getTsaServerUrl();
        if (tsaUrl != null && !tsaUrl.isEmpty()) {
            setTimestamp(true);
        }

        // Set inFile from the first positional argument
        if (files != null && !files.isEmpty()) {
            setInFile(files.get(0).getAbsolutePath());
        }
    }

    // ---- Convenience methods ----

    private String charArrToStr(final char[] aCharArr) {
        return aCharArr == null ? "" : new String(aCharArr);
    }

    public String getEffectiveOutFile() {
        String tmpOut = StringUtils.defaultIfBlank(outFile, null);
        if (tmpOut == null) {
            String tmpExtension = "";
            String tmpNameBase = StringUtils.defaultIfBlank(getInFile(), null);
            if (tmpNameBase == null) {
                tmpOut = "signed.pdf";
            } else {
                if (tmpNameBase.toLowerCase().endsWith(".pdf")) {
                    final int tmpBaseLen = tmpNameBase.length() - 4;
                    tmpExtension = tmpNameBase.substring(tmpBaseLen);
                    tmpNameBase = tmpNameBase.substring(0, tmpBaseLen);
                }
                tmpOut = tmpNameBase + Constants.DEFAULT_OUT_SUFFIX + tmpExtension;
            }
        }
        return tmpOut;
    }

    // ---- Getters and Setters ----

    public List<File> getFiles() {
        return files;
    }

    public void setFiles(List<File> files) {
        this.files = files;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keystoreType) {
        this.keyStoreType = keystoreType;
    }

    // Compatibility aliases
    public String getKsType() {
        return keyStoreType;
    }

    public void setKsType(String ksType) {
        this.keyStoreType = ksType;
    }

    public File getKeyStoreFile() {
        return keyStoreFile;
    }

    public void setKeyStoreFile(File keystoreFile) {
        this.keyStoreFile = keystoreFile;
    }

    public String getKsFile() {
        return keyStoreFile != null ? keyStoreFile.getAbsolutePath() : null;
    }

    public void setKsFile(String ksFile) {
        this.keyStoreFile = ksFile != null ? new File(ksFile) : null;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keystorePassword) {
        this.keyStorePassword = keystorePassword;
    }

    public char[] getKeyStorePasswordAsChars() {
        return keyStorePassword == null ? null : keyStorePassword.toCharArray();
    }

    public char[] getKsPasswd() {
        return keyStorePassword == null ? null : keyStorePassword.toCharArray();
    }

    public void setKsPasswd(char[] passwd) {
        this.keyStorePassword = passwd == null ? null : new String(passwd);
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public char[] getKeyPasswordAsChars() {
        return keyPassword == null ? null : keyPassword.toCharArray();
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public char[] getKeyPasswd() {
        return keyPassword == null ? null : keyPassword.toCharArray();
    }

    public char[] getEffectiveKeyPasswd() {
        char[] kp = getKeyPasswd();
        if (kp != null && kp.length == 0) {
            kp = null;
        }
        return kp != null ? kp : getKsPasswd();
    }

    public void setKeyPasswd(char[] keyPasswd) {
        this.keyPassword = keyPasswd == null ? null : new String(keyPasswd);
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public PadesLevel getPadesLevel() {
        return padesLevel;
    }

    public void setPadesLevel(PadesLevel padesLevel) {
        this.padesLevel = padesLevel;
    }

    public boolean isPrintHelp() {
        return printHelp;
    }

    public void setPrintHelp(boolean printHelp) {
        this.printHelp = printHelp;
    }

    public boolean isPrintVersion() {
        return printVersion;
    }

    public void setPrintVersion(boolean printVersion) {
        this.printVersion = printVersion;
    }

    public boolean isQuiet() {
        return quiet;
    }

    public void setQuiet(boolean quiet) {
        this.quiet = quiet;
    }

    public boolean isListKeyStores() {
        return listKeyStores;
    }

    public void setListKeyStores(boolean listKeyStores) {
        this.listKeyStores = listKeyStores;
    }

    public boolean isListKeys() {
        return listKeys;
    }

    public void setListKeys(boolean listKeys) {
        this.listKeys = listKeys;
    }

    public String getOutSuffix() {
        return outSuffix;
    }

    public void setOutSuffix(String outSuffix) {
        this.outSuffix = outSuffix;
    }

    public File getOutDirectory() {
        return outDirectory;
    }

    public void setOutDirectory(File outDirectory) {
        this.outDirectory = outDirectory;
    }

    public String getOutPrefix() {
        if (outPrefix == null)
            outPrefix = "";
        return outPrefix;
    }

    public void setOutPrefix(String outPrefix) {
        this.outPrefix = outPrefix;
    }

    public String getOutPath() {
        String tmpResult;
        if (StringUtils.isEmpty(outPath)) {
            tmpResult = "./";
        } else {
            tmpResult = outPath.replaceAll("\\\\", "/");
            if (!tmpResult.endsWith("/")) {
                tmpResult = tmpResult + "/";
            }
        }
        return tmpResult;
    }

    public void setOutPath(String outPath) {
        this.outPath = outPath;
    }

    public boolean isDisableValidityCheck() {
        return disableValidityCheck;
    }

    public void setDisableValidityCheck(boolean disableValidityCheck) {
        this.disableValidityCheck = disableValidityCheck;
    }

    public boolean isDisableKeyUsageCheck() {
        return disableKeyUsageCheck;
    }

    public void setDisableKeyUsageCheck(boolean disableKeyUsageCheck) {
        this.disableKeyUsageCheck = disableKeyUsageCheck;
    }

    public boolean isDisableCriticalExtensionsCheck() {
        return disableCriticalExtensionsCheck;
    }

    public void setDisableCriticalExtensionsCheck(boolean disableCriticalExtensionsCheck) {
        this.disableCriticalExtensionsCheck = disableCriticalExtensionsCheck;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public TsaConfig getTsaConfig() {
        return tsaConfig;
    }

    public TrustConfig getTrustConfig() {
        return trustConfig;
    }

    // Signature Metadata

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getContact() {
        return contact;
    }

    public void setContact(String contact) {
        this.contact = contact;
    }

    public String getSignerName() {
        return signerName;
    }

    public void setSignerName(String signerName) {
        this.signerName = signerName;
    }

    // Visible Signature

    public boolean isVisible() {
        return visible;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
    }

    public int getPage() {
        return page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public float getPositionLLX() {
        return positionLLX;
    }

    public void setPositionLLX(float positionLLX) {
        this.positionLLX = positionLLX;
    }

    public float getPositionLLY() {
        return positionLLY;
    }

    public void setPositionLLY(float positionLLY) {
        this.positionLLY = positionLLY;
    }

    public float getPositionURX() {
        return positionURX;
    }

    public void setPositionURX(float positionURX) {
        this.positionURX = positionURX;
    }

    public float getPositionURY() {
        return positionURY;
    }

    public void setPositionURY(float positionURY) {
        this.positionURY = positionURY;
    }

    public String getL2Text() {
        return l2Text;
    }

    public void setL2Text(String l2Text) {
        this.l2Text = l2Text;
    }

    public float getL2TextFontSize() {
        if (l2TextFontSize <= 0f) {
            l2TextFontSize = 10.0f;
        }
        return l2TextFontSize;
    }

    public void setL2TextFontSize(float l2TextFontSize) {
        this.l2TextFontSize = l2TextFontSize;
    }

    public String getBgImgPath() {
        return StringUtils.defaultIfBlank(bgImgPath, null);
    }

    public void setBgImgPath(String bgImgPath) {
        this.bgImgPath = bgImgPath;
    }

    // Encryption

    public PDFEncryption getPdfEncryption() {
        if (pdfEncryption == null) {
            pdfEncryption = PDFEncryption.NONE;
        }
        return pdfEncryption;
    }

    public void setPdfEncryption(PDFEncryption pdfEncryption) {
        this.pdfEncryption = pdfEncryption;
    }

    public void setPdfEncryption(String aValue) {
        PDFEncryption enumInstance = null;
        if (aValue != null) {
            try {
                enumInstance = PDFEncryption.valueOf(aValue.toUpperCase(Locale.ENGLISH));
            } catch (Exception e) {
                // fallback to null
            }
        }
        setPdfEncryption(enumInstance);
    }

    public char[] getPdfOwnerPwd() {
        return pdfOwnerPwd;
    }

    public String getPdfOwnerPwdStr() {
        return charArrToStr(pdfOwnerPwd);
    }

    public void setPdfOwnerPwd(char[] pdfOwnerPwd) {
        this.pdfOwnerPwd = pdfOwnerPwd;
    }

    public void setPdfOwnerPwd(String aPasswd) {
        setPdfOwnerPwd(aPasswd == null ? null : aPasswd.toCharArray());
    }

    public char[] getPdfUserPwd() {
        return pdfUserPwd;
    }

    public String getPdfUserPwdStr() {
        return charArrToStr(pdfUserPwd);
    }

    public void setPdfUserPwd(char[] pdfUserPwd) {
        this.pdfUserPwd = pdfUserPwd;
    }

    public void setPdfUserPwd(String aPasswd) {
        setPdfUserPwd(aPasswd == null ? null : aPasswd.toCharArray());
    }

    public PrintRight getRightPrinting() {
        if (rightPrinting == null) {
            rightPrinting = PrintRight.ALLOW_PRINTING;
        }
        return rightPrinting;
    }

    public void setRightPrinting(PrintRight rightPrinting) {
        this.rightPrinting = rightPrinting;
    }

    public void setRightPrinting(String aValue) {
        PrintRight printRight = null;
        if (aValue != null) {
            try {
                printRight = PrintRight.valueOf(aValue.toUpperCase(Locale.ENGLISH));
            } catch (Exception e) {
                // fallback to null
            }
        }
        setRightPrinting(printRight);
    }

    public boolean isRightCopy() {
        return rightCopy;
    }

    public void setRightCopy(boolean rightCopy) {
        this.rightCopy = rightCopy;
    }

    public boolean isRightAssembly() {
        return rightAssembly;
    }

    public void setRightAssembly(boolean rightAssembly) {
        this.rightAssembly = rightAssembly;
    }

    public boolean isRightFillIn() {
        return rightFillIn;
    }

    public void setRightFillIn(boolean rightFillIn) {
        this.rightFillIn = rightFillIn;
    }

    public boolean isRightScreanReaders() {
        return rightScreanReaders;
    }

    public void setRightScreanReaders(boolean rightScreanReaders) {
        this.rightScreanReaders = rightScreanReaders;
    }

    public boolean isRightModifyAnnotations() {
        return rightModifyAnnotations;
    }

    public void setRightModifyAnnotations(boolean rightModifyAnnotations) {
        this.rightModifyAnnotations = rightModifyAnnotations;
    }

    public boolean isRightModifyContents() {
        return rightModifyContents;
    }

    public void setRightModifyContents(boolean rightModifyContents) {
        this.rightModifyContents = rightModifyContents;
    }

    // Hash and Certification

    public HashAlgorithm getHashAlgorithm() {
        if (hashAlgorithm == null) {
            hashAlgorithm = HashAlgorithm.SHA256;
        }
        return hashAlgorithm;
    }

    public void setHashAlgorithm(HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public void setHashAlgorithm(String aValue) {
        HashAlgorithm hashAlg = null;
        if (StringUtils.isNotEmpty(aValue)) {
            try {
                hashAlg = HashAlgorithm.valueOf(aValue.toUpperCase(Locale.ENGLISH));
            } catch (Exception e) {
                // fallback to null
            }
        }
        setHashAlgorithm(hashAlg);
    }

    public CertificationLevel getCertLevel() {
        if (certLevel == null) {
            certLevel = CertificationLevel.NOT_CERTIFIED;
        }
        return certLevel;
    }

    public void setCertLevel(CertificationLevel certLevel) {
        this.certLevel = certLevel;
    }

    public void setCertLevel(String aValue) {
        CertificationLevel cl = null;
        if (aValue != null) {
            try {
                cl = CertificationLevel.valueOf(aValue.toUpperCase(Locale.ENGLISH));
            } catch (Exception e) {
                // fallback to null
            }
        }
        setCertLevel(cl);
    }

    // TSA enhancements

    public ServerAuthentication getTsaServerAuthn() {
        if (tsaServerAuthn == null) {
            tsaServerAuthn = ServerAuthentication.NONE;
        }
        return tsaServerAuthn;
    }

    public void setTsaServerAuthn(ServerAuthentication tsaServerAuthn) {
        this.tsaServerAuthn = tsaServerAuthn;
    }

    public void setTsaServerAuthn(String aValue) {
        ServerAuthentication enumInstance = null;
        if (aValue != null) {
            try {
                enumInstance = ServerAuthentication.valueOf(aValue.toUpperCase(Locale.ENGLISH));
            } catch (Exception e) {
                // fallback to null
            }
        }
        setTsaServerAuthn(enumInstance);
    }

    public String getTsaHashAlg() {
        return tsaHashAlg;
    }

    public void setTsaHashAlg(String tsaHashAlg) {
        this.tsaHashAlg = tsaHashAlg;
    }

    // Programmatic fields

    public String getInFile() {
        return inFile;
    }

    public void setInFile(String inFile) {
        this.inFile = inFile;
    }

    public String getOutFile() {
        return outFile;
    }

    public void setOutFile(String outFile) {
        this.outFile = outFile;
    }

    public boolean isTimestamp() {
        return timestamp;
    }

    public void setTimestamp(boolean timestamp) {
        this.timestamp = timestamp;
    }

    // TSA convenience methods (delegate to TsaConfig)
    public void setTsaUrl(String url) {
        tsaConfig.setTsaServerUrl(url);
    }

    public String getTsaUrl() {
        return tsaConfig.getTsaServerUrl();
    }

    public void setTsaUser(String user) {
        tsaConfig.setTsaUser(user);
    }

    public String getTsaUser() {
        return tsaConfig.getTsaUser();
    }

    public void setTsaPasswd(String password) {
        tsaConfig.setTsaPassword(password);
    }

    public String getTsaPasswd() {
        return tsaConfig.getTsaPassword();
    }

    public void setTsaPolicy(String policyOid) {
        tsaConfig.setTsaPolicyOid(policyOid);
    }

    public String getTsaPolicy() {
        return tsaConfig.getTsaPolicyOid();
    }

}
