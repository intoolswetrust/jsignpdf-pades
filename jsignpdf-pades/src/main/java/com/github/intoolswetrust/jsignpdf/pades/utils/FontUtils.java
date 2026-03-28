package com.github.intoolswetrust.jsignpdf.pades.utils;

import java.io.InputStream;

import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.DSSFont;

/**
 * Utilities for handling fonts in visible signature.
 *
 * @author Josef Cacek
 */
public class FontUtils {

    private static final String DEFAULT_FONT_PATH = "/com/github/intoolswetrust/jsignpdf/pades/fonts/DejaVuSans.ttf";

    private static DSSFont l2baseFont;

    /**
     * Returns DSSFont for text of visible signature.
     *
     * @return DSSFont instance or null
     */
    public static synchronized DSSFont getL2BaseFont() {
        if (l2baseFont == null) {
            try {
                InputStream is = FontUtils.class.getResourceAsStream(DEFAULT_FONT_PATH);
                if (is != null) {
                    l2baseFont = new DSSFileFont(is);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return l2baseFont;
    }
}
