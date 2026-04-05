package com.github.intoolswetrust.jsignpdf.pades.config;

import java.io.File;

import com.beust.jcommander.Parameter;

public class VisibleSignatureConfig {

    @Parameter(names = { "--visible-signature", "-V" }, description = "Enable visible signature")
    private boolean visible;

    @Parameter(names = "--add-blank-page", description = "Add a blank page for the visible signature")
    private boolean addBlankPage;

    @Parameter(names = "--image-only", description = "Image-only visible signature (no text)")
    private boolean imageOnly;

    @Parameter(names = { "-pg", "--page" }, description = "Page for visible signature")
    private int page = 1;

    @Parameter(names = "-llx", description = "Lower left X coordinate of visible signature")
    private float positionLLX = 0;

    @Parameter(names = "-lly", description = "Lower left Y coordinate of visible signature")
    private float positionLLY = 0;

    @Parameter(names = "-urx", description = "Upper right X coordinate of visible signature")
    private float positionURX = 100;

    @Parameter(names = "-ury", description = "Upper right Y coordinate of visible signature")
    private float positionURY = 100;

    @Parameter(names = { "-t", "--text" }, description = "Text content for visible signature")
    private String text;

    @Parameter(names = { "-ff", "--font-file" }, description = "TTF Font file to be used for visible signature text")
    private File fontFile;

    @Parameter(names = { "-fs", "--font-size" }, description = "Font size for visible signature text")
    private float textFontSize = 10.0f;

    @Parameter(names = "--bg-path", description = "Background image path for visible signature")
    private String bgImgPath;

    public boolean isVisible() {
        return visible;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
    }

    public boolean isAddBlankPage() {
        return addBlankPage;
    }

    public void setAddBlankPage(boolean addBlankPage) {
        this.addBlankPage = addBlankPage;
    }

    public boolean isImageOnly() {
        return imageOnly;
    }

    public void setImageOnly(boolean imageOnly) {
        this.imageOnly = imageOnly;
    }

    public int getPage() {
        return page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public float getPositionLLX() {
        return positionLLX;
    }

    public void setPositionLLX(float positionLLX) {
        this.positionLLX = positionLLX;
    }

    public float getPositionLLY() {
        return positionLLY;
    }

    public void setPositionLLY(float positionLLY) {
        this.positionLLY = positionLLY;
    }

    public float getPositionURX() {
        return positionURX;
    }

    public void setPositionURX(float positionURX) {
        this.positionURX = positionURX;
    }

    public float getPositionURY() {
        return positionURY;
    }

    public void setPositionURY(float positionURY) {
        this.positionURY = positionURY;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public File getFontFile() {
        return fontFile;
    }

    public void setFontFile(File fontFile) {
        this.fontFile = fontFile;
    }

    public float getTextFontSize() {
        return textFontSize;
    }

    public void setTextFontSize(float textFontSize) {
        this.textFontSize = textFontSize;
    }

    public String getBgImgPath() {
        return bgImgPath;
    }

    public void setBgImgPath(String bgImgPath) {
        this.bgImgPath = bgImgPath;
    }
}
