package com.github.intoolswetrust.jsignpdf.pades.validator;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;

public class ValidationResult {

    private final Reports reports;

    public ValidationResult(Reports reports) {
        this.reports = reports;
    }

    public SimpleReport getSimpleReport() {
        return reports.getSimpleReport();
    }

    public DetailedReport getDetailedReport() {
        return reports.getDetailedReport();
    }

    public DiagnosticData getDiagnosticData() {
        return reports.getDiagnosticData();
    }

    public boolean isAllValid() {
        SimpleReport sr = getSimpleReport();
        return sr.getSignaturesCount() > 0 && sr.getValidSignaturesCount() == sr.getSignaturesCount();
    }

    public int getSignatureCount() {
        return getSimpleReport().getSignaturesCount();
    }

    public int getValidSignatureCount() {
        return getSimpleReport().getValidSignaturesCount();
    }

    public String getXmlSimpleReport() {
        return reports.getXmlSimpleReport();
    }

    public String getXmlEtsiReport() {
        return reports.getXmlValidationReport();
    }
}
