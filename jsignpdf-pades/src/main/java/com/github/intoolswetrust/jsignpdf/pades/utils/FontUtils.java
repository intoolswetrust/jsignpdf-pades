package com.github.intoolswetrust.jsignpdf.pades.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.logging.Level;

import com.github.intoolswetrust.jsignpdf.pades.Constants;

import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.DSSFont;

/**
 * Utilities for handling fonts in visible signature.
 */
public class FontUtils {

    private static final String DEFAULT_EMBEDDED_FONT_PATH = "/com/github/intoolswetrust/jsignpdf/pades/fonts/DejaVuSans.ttf";

    /**
     * Returns DSSFont for text of visible signature.
     *
     * @return DSSFont instance or null
     */
    public static DSSFont getVisibleSignatureFont(File fontFile) {
        DSSFont font = null;
        try (InputStream is = fontFile != null ? new FileInputStream(fontFile)
                : FontUtils.class.getResourceAsStream(DEFAULT_EMBEDDED_FONT_PATH)) {
            if (is != null) {
                font = new DSSFileFont(is);
            }
        } catch (Exception e) {
            Constants.LOGGER.log(Level.SEVERE, "Font loading failed.", e);
        }
        return font;
    }
}
