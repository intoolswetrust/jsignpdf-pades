package com.github.intoolswetrust.jsignpdf.pades.validator;

import java.util.logging.Level;
import java.io.File;
import java.util.logging.Logger;

import com.github.intoolswetrust.jsignpdf.pades.common.TrustedCertSourcesProvider;
import com.github.intoolswetrust.jsignpdf.pades.validator.config.ValidatorConfig;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class SignatureValidator {

    private static final Logger LOGGER = Logger.getLogger(SignatureValidator.class.getPackage().getName());

    private final ValidatorConfig config;

    public SignatureValidator(ValidatorConfig config) {
        this.config = config;
    }

    public ValidationResult validate(File pdfFile) {
        DSSDocument document = new FileDocument(pdfFile);

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        configureTrust(verifier);
        if (!config.isSkipRevocation()) {
            verifier.setAIASource(new DefaultAIASource());
            verifier.setOcspSource(new OnlineOCSPSource());
            verifier.setCrlSource(new OnlineCRLSource());
        }

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
        validator.setCertificateVerifier(verifier);

        Reports reports = validator.validateDocument();
        return new ValidationResult(reports);
    }

    private void configureTrust(CommonCertificateVerifier verifier) {
        try {
            TrustedCertSourcesProvider provider = new TrustedCertSourcesProvider(config.getTrustConfig());
            CertificateSource[] sources = provider.createTrustedCertSources();
            if (sources.length > 0) {
                verifier.setTrustedCertSources(sources);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to configure trust sources", e);
        }
    }
}
