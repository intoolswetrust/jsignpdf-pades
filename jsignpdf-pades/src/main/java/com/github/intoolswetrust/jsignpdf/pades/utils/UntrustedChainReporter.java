package com.github.intoolswetrust.jsignpdf.pades.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/**
 * Turns the opaque untrusted-chain failure DSS raises for the LT / LTA levels into something actionable. When
 * revocation data cannot be collected because a certificate chain is not anchored, DSS names the offending
 * certificates only by their token id ({@code C-<SHA-256 hex>}) — which nobody can map back to a CA in order to
 * add it with {@code --trust-certificate-file} or {@code --trust-keystore-file}.
 *
 * <p>
 * This reporter re-derives those token ids from the certificates we already hold — the signer chain, and the
 * timestamp chain captured by {@link CapturingTspSource} — and, for each id the failure mentions, reports its
 * subject, its issuer, and which chain it came from. The fingerprint is kept as a secondary identifier so the
 * report still cross-references the raw DSS error.
 * </p>
 */
public class UntrustedChainReporter {

    /** DSS certificate token id as it appears in the failure: {@code C-} + uppercase SHA-256 hex (64 chars). */
    private static final Pattern TOKEN_ID = Pattern.compile("C-[0-9A-Fa-f]{64}");

    private UntrustedChainReporter() {
    }

    /**
     * Builds the human-readable detail block for an untrusted-chain failure.
     *
     * @param error       the failure DSS threw; its message, and those of its causes, carry the token ids
     * @param signerChain the signer's certificate chain (leaf first), or {@code null}
     * @param tsaChain    the timestamp certificates captured while signing, or {@code null} when none were
     *                    captured (the failure may have happened before the TSA replied)
     * @return the detail block, or an empty string when none of the mentioned certificates could be identified
     */
    public static String describe(Throwable error, Certificate[] signerChain,
            Collection<? extends X509Certificate> tsaChain) {
        Set<String> tokenIds = collectTokenIds(error);
        if (tokenIds.isEmpty()) {
            return "";
        }
        Map<String, X509Certificate> signerIndex = index(toX509List(signerChain));
        Map<String, X509Certificate> tsaIndex = index(tsaChain);

        StringBuilder lines = new StringBuilder();
        for (String tokenId : tokenIds) {
            final String role;
            X509Certificate cert = signerIndex.get(tokenId);
            if (cert != null) {
                role = "Signer chain certificate";
            } else {
                cert = tsaIndex.get(tokenId);
                if (cert == null) {
                    // A certificate in neither chain we hold (e.g. one fetched over AIA): leave it to the raw
                    // DSS message rather than adding a line that only repeats the fingerprint.
                    continue;
                }
                role = "Timestamp chain certificate";
            }
            if (lines.length() > 0) {
                lines.append(System.lineSeparator());
            }
            lines.append("  ").append(role).append(": ").append(subjectOf(cert)).append(" (issued by ")
                    .append(issuerOf(cert)).append(", ").append(tokenId).append(')');
        }
        if (lines.length() == 0) {
            return "";
        }
        return "Add the issuing CA of the following certificate(s) as a trust anchor"
                + " (--trust-certificate-file / --trust-keystore-file / --trust-use-default-lotl):"
                + System.lineSeparator() + lines;
    }

    /** Collects the distinct token ids from the throwable and its causes, preserving the order DSS named them. */
    private static Set<String> collectTokenIds(Throwable error) {
        Set<String> ids = new LinkedHashSet<>();
        for (Throwable t = error; t != null; t = t.getCause()) {
            String message = t.getMessage();
            if (message != null) {
                Matcher matcher = TOKEN_ID.matcher(message);
                while (matcher.find()) {
                    ids.add(matcher.group().toUpperCase());
                }
            }
        }
        return ids;
    }

    /** Indexes certificates by their DSS token id ({@code C-} + uppercase SHA-256 hex of the DER encoding). */
    private static Map<String, X509Certificate> index(Collection<? extends X509Certificate> certs) {
        Map<String, X509Certificate> index = new LinkedHashMap<>();
        if (certs == null) {
            return index;
        }
        final MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            return index; // Mandated by the platform; unreachable in practice.
        }
        for (X509Certificate cert : certs) {
            if (cert == null) {
                continue;
            }
            try {
                String tokenId = "C-" + HexFormat.of().withUpperCase().formatHex(sha256.digest(cert.getEncoded()));
                index.putIfAbsent(tokenId, cert);
            } catch (Exception e) {
                // A certificate that cannot be re-encoded simply stays unidentified in the report.
            }
        }
        return index;
    }

    private static List<X509Certificate> toX509List(Certificate[] chain) {
        List<X509Certificate> out = new ArrayList<>();
        if (chain != null) {
            for (Certificate cert : chain) {
                if (cert instanceof X509Certificate x509) {
                    out.add(x509);
                }
            }
        }
        return out;
    }

    private static String subjectOf(X509Certificate cert) {
        return commonNameOrDn(cert.getSubjectX500Principal());
    }

    private static String issuerOf(X509Certificate cert) {
        return commonNameOrDn(cert.getIssuerX500Principal());
    }

    /** Returns the principal's CN when it has one, otherwise its full DN. */
    private static String commonNameOrDn(X500Principal principal) {
        try {
            LdapName ldapName = new LdapName(principal.getName());
            for (Rdn rdn : ldapName.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
        } catch (Exception e) {
            // fall through to the full DN
        }
        return principal.getName();
    }
}
