package com.github.intoolswetrust.jsignpdf.pades.validator;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.beust.jcommander.JCommander;
import com.github.intoolswetrust.jsignpdf.pades.validator.config.ValidatorConfig;

public class Main {

    private static final Logger LOGGER = Logger.getLogger(Main.class.getPackage().getName());

    public static void main(String[] args) {
        ValidatorConfig config = new ValidatorConfig();
        JCommander jcmd = JCommander.newBuilder().addObject(config).build();

        try {
            jcmd.parse(args);
        } catch (Exception e) {
            System.err.println("Error parsing arguments: " + e.getMessage());
            System.exit(2);
        }

        if (config.isHelp()) {
            jcmd.usage();
            System.exit(0);
        }

        if (config.isQuiet()) {
            LOGGER.setLevel(Level.OFF);
        }

        if (config.getFiles().isEmpty()) {
            System.err.println("No PDF files specified. Use --help for usage.");
            System.exit(2);
        }

        try {
            SignatureValidator validator = new SignatureValidator(config);
            boolean allValid = true;

            for (File pdfFile : config.getFiles()) {
                if (!pdfFile.exists() || !pdfFile.isFile()) {
                    System.err.println("File not found: " + pdfFile);
                    System.exit(2);
                }

                ValidationResult result = validator.validate(pdfFile);

                if (!config.isQuiet()) {
                    if (config.getFiles().size() > 1) {
                        System.out.println("File: " + pdfFile.getName());
                    }
                    String output = ValidationOutput.format(result, config.getFormat(), config.isVerbose());
                    System.out.print(output);
                }

                if (!result.isAllValid()) {
                    allValid = false;
                }
            }

            System.exit(allValid ? 0 : 1);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Validation error", e);
            System.err.println("Error: " + e.getMessage());
            System.exit(2);
        }
    }
}
