package com.github.intoolswetrust.jsignpdf.pades.validator.config;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import com.beust.jcommander.converters.FileConverter;

import com.github.intoolswetrust.jsignpdf.pades.common.TrustConfig;

public class ValidatorConfig {

    @Parameter(converter = FileConverter.class, description = "PDF files to validate")
    private List<File> files = new ArrayList<>();

    @Parameter(names = {"--help", "-h"}, help = true, description = "Prints this help")
    private boolean help;

    @Parameter(names = {"--format", "-f"}, description = "Output format: TEXT (default), XML, ETSI, JSON")
    private OutputFormat format = OutputFormat.TEXT;

    @Parameter(names = "--verbose", description = "Include detailed report information")
    private boolean verbose;

    @Parameter(names = {"--quiet", "-q"}, description = "Only output validation result (PASSED/FAILED)")
    private boolean quiet;

    @Parameter(names = "--skip-revocation", description = "Skip online revocation checks (OCSP/CRL)")
    private boolean skipRevocation;

    @ParametersDelegate
    private final TrustConfig trustConfig = new TrustConfig();

    public List<File> getFiles() { return files; }
    public boolean isHelp() { return help; }
    public OutputFormat getFormat() { return format; }
    public boolean isVerbose() { return verbose; }
    public boolean isQuiet() { return quiet; }
    public boolean isSkipRevocation() { return skipRevocation; }
    public TrustConfig getTrustConfig() { return trustConfig; }
}
