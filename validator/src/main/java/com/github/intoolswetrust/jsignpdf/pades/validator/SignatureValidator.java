package com.github.intoolswetrust.jsignpdf.pades.validator;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.github.intoolswetrust.jsignpdf.pades.validator.config.TrustConfig;
import com.github.intoolswetrust.jsignpdf.pades.validator.config.ValidatorConfig;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
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
        TrustConfig trustConfig = config.getTrustConfig();
        List<CertificateSource> trustedSources = new ArrayList<>();

        if (trustConfig.isUseDefaultLotl()) {
            LOGGER.info("Default EU LOTL trust enabled");
        }

        for (File certFile : trustConfig.getCertificateFiles()) {
            try {
                CommonTrustedCertificateSource source = new CommonTrustedCertificateSource();
                source.addCertificate(DSSUtils.loadCertificate(certFile));
                trustedSources.add(source);
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Failed to load certificate: " + certFile, e);
            }
        }

        for (String certUrl : trustConfig.getCertificateUrls()) {
            try (InputStream is = new URL(certUrl).openStream()) {
                CommonTrustedCertificateSource source = new CommonTrustedCertificateSource();
                source.addCertificate(DSSUtils.loadCertificate(is));
                trustedSources.add(source);
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Failed to load certificate from URL: " + certUrl, e);
            }
        }

        File truststoreFile = trustConfig.getKeystoreFile();
        if (truststoreFile != null) {
            try {
                String ksPwd = trustConfig.getKeystorePassword();
                KeyStoreCertificateSource source = new KeyStoreCertificateSource(
                        truststoreFile, trustConfig.getKeystoreType(),
                        ksPwd != null ? ksPwd.toCharArray() : null);
                trustedSources.add(source);
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Failed to load truststore: " + truststoreFile, e);
            }
        }

        if (!trustedSources.isEmpty()) {
            verifier.setTrustedCertSources(trustedSources.toArray(new CertificateSource[0]));
        }
    }
}
