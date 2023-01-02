package com.github.intoolswetrust.jsignpdf.pades;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import com.github.intoolswetrust.jsignpdf.pades.config.TrustConfig;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;

public class TrustedCertSourcesProvider {

    private final TrustConfig trustConfig;

    public TrustedCertSourcesProvider(TrustConfig trustConfig) {
        this.trustConfig = trustConfig;
    }

    public CertificateSource[] createTrustedCertSources() throws MalformedURLException, IOException {
        List<CertificateSource> trustedSources = new ArrayList<>();
        LOTLSource[] lotlSources = getLotlSources();
        if (lotlSources.length > 0) {
            TLValidationJob tlValidationJob = new TLValidationJob();
            tlValidationJob.setOnlineDataLoader(new FileCacheDataLoader(new CommonsDataLoader()));
            tlValidationJob.setListOfTrustedListSources(lotlSources);
            TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
            tlValidationJob.setTrustedListCertificateSource(trustedListsCertificateSource);
            tlValidationJob.onlineRefresh();
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
            KeyStoreCertificateSource source = new KeyStoreCertificateSource(truststoreFile, trustConfig.getKeystoreType(),
                    trustConfig.getKeystorePassword());
            trustedSources.add(source);
        }
        return trustedSources.toArray(new CertificateSource[trustedSources.size()]);
    }

    private LOTLSource[] getLotlSources() {
        List<LOTLSource> lotlSources = new ArrayList<>();
        if (trustConfig.isUseDefaultLotl()) {
            lotlSources.add(new LOTLSource());
        }
        for (String url : trustConfig.getLotlUrls()) {
            LOTLSource lotlSource = new LOTLSource();
            lotlSource.setUrl(url);
            lotlSource.setCertificateSource(new CommonCertificateSource());
            // lotlSource.setPivotSupport(true);
        }
        return lotlSources.toArray(new LOTLSource[lotlSources.size()]);
    }
}
