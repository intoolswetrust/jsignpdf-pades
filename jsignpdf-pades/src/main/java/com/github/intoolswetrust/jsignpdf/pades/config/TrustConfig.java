package com.github.intoolswetrust.jsignpdf.pades.config;

import java.io.File;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

import com.beust.jcommander.Parameter;

public class TrustConfig {

    @Parameter(names = { "--trust-lotl-url" }, description = "URL to a List Of Trusted Lists")
    private List<String> lotlUrls = new ArrayList<>();

    @Parameter(names = { "--trust-certificate-url" }, description = "URL to a trusted X.509 certificate")
    private List<String> certificateUrls = new ArrayList<>();

    @Parameter(names = { "--trust-certificate-file" }, description = "File path to a trusted X.509 certificate")
    private List<File> certificateFiles = new ArrayList<>();

    @Parameter(names = { "--trust-keystore-file" }, description = "File path to a truststore")
    private File keystoreFile;

    @Parameter(names = { "--trust-keystore-password" }, description = "Truststore password")
    private String keystorePassword;

    @Parameter(names = { "--trust-keystore-type" }, description = "Truststore type")
    private String keystoreType = KeyStore.getDefaultType();

    @Parameter(names = { "--trust-use-default-lotl" }, description = "Use default List Of Trusted Lists (EU)")
    private boolean useDefaultLotl;

    public List<String> getLotlUrls() {
        return lotlUrls;
    }

    public void setLotlUrls(List<String> lotlUrls) {
        this.lotlUrls = lotlUrls;
    }

    public List<String> getCertificateUrls() {
        return certificateUrls;
    }

    public void setCertificateUrls(List<String> certificateUrls) {
        this.certificateUrls = certificateUrls;
    }

    public List<File> getCertificateFiles() {
        return certificateFiles;
    }

    public void setCertificateFiles(List<File> certificateFiles) {
        this.certificateFiles = certificateFiles;
    }

    public File getKeystoreFile() {
        return keystoreFile;
    }

    public void setKeystoreFile(File keystoreFile) {
        this.keystoreFile = keystoreFile;
    }

    public String getKeystorePassword() {
        return keystorePassword;
    }

    public void setKeystorePassword(String keystorePassword) {
        this.keystorePassword = keystorePassword;
    }

    public String getKeystoreType() {
        return keystoreType;
    }

    public void setKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
    }

    public boolean isUseDefaultLotl() {
        return useDefaultLotl;
    }

    public void setUseDefaultLotl(boolean useDefaultLotl) {
        this.useDefaultLotl = useDefaultLotl;
    }    


}
