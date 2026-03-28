package com.github.intoolswetrust.jsignpdf.pades.types;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public enum HashAlgorithm {
    SHA1(DigestAlgorithm.SHA1),
    SHA256(DigestAlgorithm.SHA256),
    SHA384(DigestAlgorithm.SHA384),
    SHA512(DigestAlgorithm.SHA512),
    RIPEMD160(DigestAlgorithm.RIPEMD160);

    private final DigestAlgorithm dssDigestAlgorithm;

    HashAlgorithm(DigestAlgorithm dssDigestAlgorithm) {
        this.dssDigestAlgorithm = dssDigestAlgorithm;
    }

    public DigestAlgorithm toDssDigestAlgorithm() {
        return dssDigestAlgorithm;
    }
}
