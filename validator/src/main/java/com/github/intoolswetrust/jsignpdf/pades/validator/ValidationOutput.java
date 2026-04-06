package com.github.intoolswetrust.jsignpdf.pades.validator;

import java.util.List;

import com.github.intoolswetrust.jsignpdf.pades.validator.config.OutputFormat;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;

public class ValidationOutput {

    public static String format(ValidationResult result, OutputFormat format, boolean verbose) {
        return switch (format) {
            case XML  -> result.getXmlSimpleReport();
            case ETSI -> result.getXmlEtsiReport();
            case JSON -> formatJson(result);
            case TEXT  -> formatText(result, verbose);
        };
    }

    private static String formatText(ValidationResult result, boolean verbose) {
        SimpleReport sr = result.getSimpleReport();
        StringBuilder sb = new StringBuilder();

        sb.append("Signatures: ").append(sr.getSignaturesCount()).append('\n');
        sb.append("Valid: ").append(sr.getValidSignaturesCount()).append('\n');
        sb.append('\n');

        for (String sigId : sr.getSignatureIdList()) {
            sb.append("Signature ").append(sigId).append(":\n");
            sb.append("  Signer:      ").append(sr.getSignedBy(sigId)).append('\n');
            sb.append("  Signing time: ").append(sr.getSigningTime(sigId)).append('\n');

            Indication indication = sr.getIndication(sigId);
            sb.append("  Indication:  ").append(indication).append('\n');
            SubIndication subIndication = sr.getSubIndication(sigId);
            if (subIndication != null) {
                sb.append("  Sub-indication: ").append(subIndication).append('\n');
            }

            if (verbose) {
                List<?> errors = sr.getAdESValidationErrors(sigId);
                if (errors != null && !errors.isEmpty()) {
                    sb.append("  Errors:\n");
                    for (Object err : errors) {
                        sb.append("    - ").append(err).append('\n');
                    }
                }
                List<?> warnings = sr.getAdESValidationWarnings(sigId);
                if (warnings != null && !warnings.isEmpty()) {
                    sb.append("  Warnings:\n");
                    for (Object warn : warnings) {
                        sb.append("    - ").append(warn).append('\n');
                    }
                }
            }
            sb.append('\n');
        }

        sb.append("Result: ").append(result.isAllValid() ? "PASSED" : "FAILED").append('\n');
        return sb.toString();
    }

    private static String formatJson(ValidationResult result) {
        SimpleReport sr = result.getSimpleReport();
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"signaturesCount\": ").append(sr.getSignaturesCount()).append(",\n");
        sb.append("  \"validSignaturesCount\": ").append(sr.getValidSignaturesCount()).append(",\n");
        sb.append("  \"valid\": ").append(result.isAllValid()).append(",\n");
        sb.append("  \"signatures\": [\n");

        List<String> sigIds = sr.getSignatureIdList();
        for (int i = 0; i < sigIds.size(); i++) {
            String sigId = sigIds.get(i);
            sb.append("    {\n");
            sb.append("      \"id\": ").append(jsonString(sigId)).append(",\n");
            sb.append("      \"signedBy\": ").append(jsonString(sr.getSignedBy(sigId))).append(",\n");
            sb.append("      \"signingTime\": ").append(jsonString(
                    sr.getSigningTime(sigId) != null ? sr.getSigningTime(sigId).toString() : null)).append(",\n");
            sb.append("      \"indication\": ").append(jsonString(sr.getIndication(sigId).name())).append(",\n");
            SubIndication subInd = sr.getSubIndication(sigId);
            sb.append("      \"subIndication\": ").append(subInd != null ? jsonString(subInd.name()) : "null").append(",\n");
            sb.append("      \"valid\": ").append(sr.isValid(sigId)).append("\n");
            sb.append("    }");
            if (i < sigIds.size() - 1) sb.append(",");
            sb.append("\n");
        }

        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static String jsonString(String value) {
        if (value == null) return "null";
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
