package com.github.intoolswetrust.jsignpdf.pades.config;

import java.io.File;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.CharArrayConverter;
import com.beust.jcommander.converters.FileConverter;

import com.github.intoolswetrust.jsignpdf.pades.types.ServerAuthentication;

public class TsaConfig {

    @Parameter(names = {"--tsa-server-url", "-ts"}, description = "Timestamp server URL")
    private String tsaServerUrl;

    @Parameter(names = {"--tsa-authentication", "-ta"}, description = "TSA authentication method (NONE, PASSWORD, CERTIFICATE)")
    private ServerAuthentication tsaServerAuthn;

    @Parameter(names = {"--tsa-key-file-type", "-tskt"}, description = "KeyStore type for TSA client-certificate authentication")
    private String tsaKeyStoreFileType;
    @Parameter(names = {"--tsa-key-file", "-tskf"}, converter = FileConverter.class, description = "KeyStore file for TSA client-certificate authentication")
    private File tsaKeyStoreFile;
    @Parameter(names = {"--tsa-key-password", "-tskp"}, converter = CharArrayConverter.class, description = "KeyStore password for TSA client-certificate authentication")
    private char[] tsaKeyStorePassword;

    @Parameter(names = {"--tsa-user", "-tsu"}, description = "Username for TSA Basic authentication")
    private String tsaUser;
    @Parameter(names = {"--tsa-password", "-tsp"}, converter = CharArrayConverter.class, description = "Password for TSA Basic authentication")
    private char[] tsaPassword;
    @Parameter(names = {"--tsa-policy-oid"}, description = "TSA policy OID")
    private String tsaPolicyOid;
    @Parameter(names = {"--tsa-hash-algorithm", "-tsh"}, description = "TSA hash algorithm")
    private String tsaHashAlgorithm;

    public String getTsaServerUrl() {
        return tsaServerUrl;
    }

    public void setTsaServerUrl(String tsaServerUrl) {
        this.tsaServerUrl = tsaServerUrl;
    }

    public String getTsaKeyStoreFileType() {
        return tsaKeyStoreFileType;
    }

    public void setTsaKeyStoreFileType(String tsaKeyStoreFileType) {
        this.tsaKeyStoreFileType = tsaKeyStoreFileType;
    }

    public File getTsaKeyStoreFile() {
        return tsaKeyStoreFile;
    }

    public void setTsaKeyStoreFile(File tsaKeyStoreFile) {
        this.tsaKeyStoreFile = tsaKeyStoreFile;
    }

    public char[] getTsaKeyStorePassword() {
        return tsaKeyStorePassword;
    }

    public void setTsaKeyStorePassword(char[] tsaKeyStorePassword) {
        this.tsaKeyStorePassword = tsaKeyStorePassword;
    }

    public String getTsaUser() {
        return tsaUser;
    }

    public void setTsaUser(String tsaUser) {
        this.tsaUser = tsaUser;
    }

    public char[] getTsaPassword() {
        return tsaPassword;
    }

    public void setTsaPassword(char[] tsaPassword) {
        this.tsaPassword = tsaPassword;
    }

    public String getTsaPolicyOid() {
        return tsaPolicyOid;
    }

    public void setTsaPolicyOid(String tsaPolicyOid) {
        this.tsaPolicyOid = tsaPolicyOid;
    }

    public String getTsaHashAlgorithm() {
        return tsaHashAlgorithm;
    }

    public void setTsaHashAlgorithm(String tsaHashAlgorithm) {
        this.tsaHashAlgorithm = tsaHashAlgorithm;
    }

    public ServerAuthentication getTsaServerAuthn() {
        return tsaServerAuthn;
    }

    public void setTsaServerAuthn(ServerAuthentication tsaServerAuthn) {
        this.tsaServerAuthn = tsaServerAuthn;
    }
}
