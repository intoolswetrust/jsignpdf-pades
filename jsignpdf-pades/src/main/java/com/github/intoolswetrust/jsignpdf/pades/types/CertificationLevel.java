package com.github.intoolswetrust.jsignpdf.pades.types;

import eu.europa.esig.dss.enumerations.CertificationPermission;

public enum CertificationLevel {
    NOT_CERTIFIED(0),
    CERTIFIED_NO_CHANGES_ALLOWED(1),
    CERTIFIED_FORM_FILLING(2),
    CERTIFIED_FORM_FILLING_AND_ANNOTATIONS(3);

    private final int level;

    CertificationLevel(int level) {
        this.level = level;
    }

    public int getLevel() {
        return level;
    }

    public CertificationPermission toDssCertificationPermission() {
        return switch (this) {
            case CERTIFIED_NO_CHANGES_ALLOWED -> CertificationPermission.NO_CHANGE_PERMITTED;
            case CERTIFIED_FORM_FILLING -> CertificationPermission.MINIMAL_CHANGES_PERMITTED;
            case CERTIFIED_FORM_FILLING_AND_ANNOTATIONS -> CertificationPermission.CHANGES_PERMITTED;
            default -> null;
        };
    }
}
