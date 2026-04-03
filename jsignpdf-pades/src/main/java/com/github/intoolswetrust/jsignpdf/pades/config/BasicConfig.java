package com.github.intoolswetrust.jsignpdf.pades.config;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
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

    @Parameter(names = { "--keystore-password", "-ksp" }, description = "KeyStore password")
    private String keyStorePassword;

    @Parameter(names = { "--key-password", "-kp" }, description = "Key password")
    private String keyPassword;

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

    // Visible Signature
    @Parameter(names = { "--visible-signature", "-V" }, description = "Enable visible signature")
    private boolean visible;

    @Parameter(names = "--add-blank-page", description = "Add a blank page for the visible signature")
    private boolean addBlankPage;

    @Parameter(names = "--image-only", description = "Image-only visible signature (no text)")
    private boolean imageOnly;

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

    @Parameter(names = { "-t", "--text" }, description = "Text content for visible signature")
    private String text;

    @Parameter(names = { "-ff", "--font-file" }, description = "TTF Font file to be used for visible signature text")
    private File fontFile;

    @Parameter(names = { "-fs", "--font-size" }, description = "Font size for visible signature text")
    private float textFontSize = 10.0f;

    @Parameter(names = "--bg-path", description = "Background image path for visible signature")
    private String bgImgPath;

    // Encryption
    @Parameter(names = { "--encrypt-before-sign" }, description = "Encrypt PDF with password before signing")
    private boolean encryptBeforeSign;

    @Parameter(names = { "--owner-password", "-opwd" }, description = "Owner password for encrypted PDF")
    private String pdfOwnerPwd;

    @Parameter(names = { "--user-password", "-upwd" }, description = "User password for encrypted PDF")
    private String pdfUserPwd;

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

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keystorePassword) {
        this.keyStorePassword = keystorePassword;
    }

    public char[] getKeyStorePasswordAsChars() {
        return keyStorePassword == null ? null : keyStorePassword.toCharArray();
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public char[] getKeyPasswordAsChars() {
        return keyPassword == null ? null : keyPassword.toCharArray();
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

    public boolean isVisible() {
        return visible;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
    }

    public boolean isAddBlankPage() {
        return addBlankPage;
    }

    public void setAddBlankPage(boolean addBlankPage) {
        this.addBlankPage = addBlankPage;
    }

    public boolean isImageOnly() {
        return imageOnly;
    }

    public void setImageOnly(boolean imageOnly) {
        this.imageOnly = imageOnly;
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

    public String getText() {
        return text;
    }

    public void setText(String l2Text) {
        this.text = l2Text;
    }

    public float getTextFontSize() {
        return textFontSize;
    }

    public void setTextFontSize(float l2TextFontSize) {
        this.textFontSize = l2TextFontSize;
    }

    public String getBgImgPath() {
        return bgImgPath;
    }

    public void setBgImgPath(String bgImgPath) {
        this.bgImgPath = bgImgPath;
    }

    public boolean isEncryptBeforeSign() {
        return encryptBeforeSign;
    }

    public void setEncryptBeforeSign(boolean encryptBeforeSign) {
        this.encryptBeforeSign = encryptBeforeSign;
    }

    public String getPdfOwnerPwd() {
        return pdfOwnerPwd;
    }

    public void setPdfOwnerPwd(String pdfOwnerPwd) {
        this.pdfOwnerPwd = pdfOwnerPwd;
    }

    public String getPdfUserPwd() {
        return pdfUserPwd;
    }

    public void setPdfUserPwd(String pdfUserPwd) {
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

    public File getFontFile() {
        return fontFile;
    }

    public boolean isInsecureRelaxTls() {
        return insecureRelaxTls;
    }
}
