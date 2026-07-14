package com.github.intoolswetrust.jsignpdf.pades.signing.validation;

import java.io.File;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * Reads back the PAdES baseline level a signed PDF actually achieved, using DSS's own validator.
 *
 * <p>
 * {@link PdfSignatureValidator} covers the structural and cryptographic properties, but it cannot tell the
 * baseline levels apart: B, T, LT and LTA all share the {@code ETSI.CAdES.detached} subfilter, and the
 * difference lives in the embedded timestamp, the DSS dictionary and the archive timestamp. Asking DSS what
 * it sees is the only assertion that distinguishes them.
 * </p>
 */
public class PadesLevelReader {

    private PadesLevelReader() {
    }

    /**
     * Returns the level of the first signature in the given signed PDF. No trust anchors are configured: the
     * level reflects the material embedded in the file, not whether the signer is trusted here.
     */
    public static SignatureLevel readLevel(File signedPdf) {
        return readLevel(signedPdf, 0);
    }

    /**
     * Returns the level of the signature at the given index.
     */
    public static SignatureLevel readLevel(File signedPdf, int signatureIndex) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(signedPdf));
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        Reports reports = validator.validateDocument();
        SimpleReport report = reports.getSimpleReport();
        if (signatureIndex >= report.getSignaturesCount()) {
            throw new IllegalArgumentException("No signature at index " + signatureIndex + " in " + signedPdf
                    + " (found " + report.getSignaturesCount() + ")");
        }
        return report.getSignatureFormat(report.getSignatureIdList().get(signatureIndex));
    }
}
