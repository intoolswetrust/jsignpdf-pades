package com.github.intoolswetrust.jsignpdf.pades.config;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import com.beust.jcommander.converters.CharArrayConverter;
import com.beust.jcommander.converters.FileConverter;

import com.github.intoolswetrust.jsignpdf.pades.common.TrustConfig;
import com.github.intoolswetrust.jsignpdf.pades.types.CertificationLevel;

import com.github.intoolswetrust.jsignpdf.pades.types.PrintRight;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public class BasicConfig {

    // Commands
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

    // Keystore
    @Parameter(names = { "--keystore-type", "-kst" }, description = "Keystore type to be loaded")
    private String keyStoreType;

    @Parameter(names = { "--keystore-file", "-ksf" }, description = "Keystore file to be used")
    private File keyStoreFile;

    @Parameter(names = { "--keystore-password", "-ksp" }, converter = CharArrayConverter.class, description = "KeyStore password")
    private char[] keyStorePassword;

    @Parameter(names = { "--key-password", "-kp" }, converter = CharArrayConverter.class, description = "Key password")
    private char[] keyPassword;

    @Parameter(names = { "--key-alias", "-ka" }, description = "Key alias to be used for signing")
    private String keyAlias;

    // Signing
    @Parameter(names = { "--pades-level", "-pl" }, description = "PAdES level")
    private PadesLevel padesLevel = PadesLevel.BASELINE_B;

    @Parameter(names = { "--digest-algorithm", "-da" }, description = "Digest algorithm used in the signature")
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

    @Parameter(names = { "--certification-level", "-cl" }, description = "Certification level")
    private CertificationLevel certLevel;

    // Output
    @Parameter(names = { "--out-suffix", "-os" }, description = "Signed file suffix to be attached to the original name")
    private String outSuffix = "_signed";

    @Parameter(names = { "--out-directory",
            "-d" }, description = "Directory to write the signed PDFs to. If not provided, the source directory of input PDF file is used.")
    private File outDirectory;

    // Certificate validation
    @Parameter(names = "--disable-validity-check", description = "Don't check certificate validity in the keystore")
    private boolean disableValidityCheck;

    @Parameter(names = "--disable-key-usage-check", description = "Don't check certificate key-usage field in the keystore")
    private boolean disableKeyUsageCheck;

    @Parameter(names = "--disable-critical-extensions-check", description = "Don't check if all certificate critical extensions are known")
    private boolean disableCriticalExtensionsCheck;

    // Signature Metadata
    @Parameter(names = { "--reason", "-r" }, description = "Reason for signature")
    private String reason;

    @Parameter(names = { "--location", "-l" }, description = "Location of signature")
    private String location;

    @Parameter(names = { "--contact", "-c" }, description = "Contact info")
    private String contact;

    @Parameter(names = { "--signer-name", "-sn" }, description = "Signer name")
    private String signerName;

    // Encryption
    @Parameter(names = { "--encrypt-before-sign" }, description = "Encrypt PDF with password before signing")
    private boolean encryptBeforeSign;

    @Parameter(names = { "--owner-password", "-opwd" }, converter = CharArrayConverter.class, description = "Owner password for encrypted PDF")
    private char[] pdfOwnerPwd;

    @Parameter(names = { "--user-password", "-upwd" }, converter = CharArrayConverter.class, description = "User password for encrypted PDF")
    private char[] pdfUserPwd;

    @Parameter(names = { "--print-right", "-pr" }, description = "Printing rights for encrypted PDF")
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

    @Parameter(names = "--insecure-relax-tls", description = "Switch to INSECURE mode and don't verify TLS connections")
    private boolean insecureRelaxTls;

    // Delegates
    @ParametersDelegate
    private final VisibleSignatureConfig visibleSignatureConfig = new VisibleSignatureConfig();

    @ParametersDelegate
    private final TsaConfig tsaConfig = new TsaConfig();

    @ParametersDelegate
    private final TrustConfig trustConfig = new TrustConfig();

    // ---- Getters and Setters ----

    public List<File> getFiles() {
        return files;
    }

    public void setFiles(List<File> files) {
        this.files = files;
    }

    public boolean isPrintHelp() {
        return printHelp;
    }

    public boolean isPrintVersion() {
        return printVersion;
    }

    public boolean isQuiet() {
        return quiet;
    }

    public boolean isListKeyStores() {
        return listKeyStores;
    }

    public boolean isListKeys() {
        return listKeys;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keystoreType) {
        this.keyStoreType = keystoreType;
    }

    public File getKeyStoreFile() {
        return keyStoreFile;
    }

    public void setKeyStoreFile(File keystoreFile) {
        this.keyStoreFile = keystoreFile;
    }

    public char[] getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(char[] keystorePassword) {
        this.keyStorePassword = keystorePassword;
    }

    public char[] getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(char[] keyPassword) {
        this.keyPassword = keyPassword;
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

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public CertificationLevel getCertLevel() {
        return certLevel;
    }

    public void setCertLevel(CertificationLevel certLevel) {
        this.certLevel = certLevel;
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

    public boolean isDisableValidityCheck() {
        return disableValidityCheck;
    }

    public boolean isDisableKeyUsageCheck() {
        return disableKeyUsageCheck;
    }

    public boolean isDisableCriticalExtensionsCheck() {
        return disableCriticalExtensionsCheck;
    }

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

    public VisibleSignatureConfig getVisibleSignatureConfig() {
        return visibleSignatureConfig;
    }

    public boolean isEncryptBeforeSign() {
        return encryptBeforeSign;
    }

    public void setEncryptBeforeSign(boolean encryptBeforeSign) {
        this.encryptBeforeSign = encryptBeforeSign;
    }

    public char[] getPdfOwnerPwd() {
        return pdfOwnerPwd;
    }

    public void setPdfOwnerPwd(char[] pdfOwnerPwd) {
        this.pdfOwnerPwd = pdfOwnerPwd;
    }

    public char[] getPdfUserPwd() {
        return pdfUserPwd;
    }

    public void setPdfUserPwd(char[] pdfUserPwd) {
        this.pdfUserPwd = pdfUserPwd;
    }

    public PrintRight getRightPrinting() {
        return rightPrinting;
    }

    public void setRightPrinting(PrintRight rightPrinting) {
        this.rightPrinting = rightPrinting;
    }

    public boolean isDisableCopy() {
        return disableCopy;
    }

    public void setDisableCopy(boolean disableCopy) {
        this.disableCopy = disableCopy;
    }

    public boolean isDisableAssembly() {
        return disableAssembly;
    }

    public void setDisableAssembly(boolean disableAssembly) {
        this.disableAssembly = disableAssembly;
    }

    public boolean isDisableFill() {
        return disableFill;
    }

    public void setDisableFill(boolean disableFill) {
        this.disableFill = disableFill;
    }

    public boolean isDisableScreenReaders() {
        return disableScreenReaders;
    }

    public void setDisableScreenReaders(boolean disableScreenReaders) {
        this.disableScreenReaders = disableScreenReaders;
    }

    public boolean isDisableModifyAnnotations() {
        return disableModifyAnnotations;
    }

    public void setDisableModifyAnnotations(boolean disableModifyAnnotations) {
        this.disableModifyAnnotations = disableModifyAnnotations;
    }

    public boolean isDisableModifyContent() {
        return disableModifyContent;
    }

    public void setDisableModifyContent(boolean disableModifyContent) {
        this.disableModifyContent = disableModifyContent;
    }

    public TsaConfig getTsaConfig() {
        return tsaConfig;
    }

    public TrustConfig getTrustConfig() {
        return trustConfig;
    }

    public boolean isInsecureRelaxTls() {
        return insecureRelaxTls;
    }
}
