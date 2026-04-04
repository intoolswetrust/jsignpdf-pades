package com.github.intoolswetrust.jsignpdf.pades;

import static com.github.intoolswetrust.jsignpdf.pades.Constants.LOGGER;
import static com.github.intoolswetrust.jsignpdf.pades.Constants.VERSION;

import java.io.File;
import java.security.Security;
import java.util.TreeSet;
import java.util.logging.Level;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;

import com.beust.jcommander.JCommander;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.config.Pkcs11Config;

public class Main {

    public static void main(String[] args) {
        int exitCode = 0;
        BasicConfig config = new BasicConfig();
        Pkcs11Config p11config = new Pkcs11Config();
        JCommander jcmd = JCommander.newBuilder().addObject(asArray(config, p11config)).build();
        jcmd.parse(args);

        try (Pkcs11Initializer p11init = new Pkcs11Initializer(p11config);
                SSLInitializer sslInit = new SSLInitializer(config)) {
            if (config.isQuiet()) {
                LOGGER.setLevel(Level.OFF);
            }
            boolean cmdUsed = false;
            if (config.isPrintVersion()) {
                System.out.println("jsignpdf-pades version " + Constants.VERSION);
                return;
            }
            if (config.isPrintHelp()) {
                cmdUsed = true;
                jcmd.usage();
            }
            if (config.isListKeyStores()) {
                cmdUsed = true;
                TreeSet<String> ksts = new TreeSet<String>(Security.getAlgorithms("KeyStore"));
                for (String kst : ksts) {
                    System.out.println(kst);
                }
            }
            if (config.isListKeys()) {
                cmdUsed = true;
                try {
                    for (String kst : KeyStoreUtils.getKeyAliases(config)) {
                        System.out.println(kst);
                    }
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Unable to list keystore content", e);
                }
            }
            boolean noFilesProvided = config.getFiles().isEmpty();
            if (noFilesProvided) {
                if (!cmdUsed) {
                    jcmd.usage();
                    exitCode = 1;
                }
            }

            if (!noFilesProvided) {
                int failCount = signFiles(config);
                if (failCount > 0) {
                    exitCode = 16 + failCount;
                }
            }
        } catch (Throwable t) {
            LOGGER.log(Level.SEVERE, "Error occured", t);
            exitCode = 2;
        } finally {
            System.exit(exitCode);
        }
    }

    private static int signFiles(BasicConfig config) {
        SignerLogic signerLogic = new SignerLogic(config);
        int successCount = 0;
        int failedCount = 0;

        for (File pdfFile : config.getFiles()) {
            File outFile = getOutputFile(pdfFile, config);

            if (signerLogic.signFile(pdfFile, outFile)) {
                successCount++;
            } else {
                failedCount++;
            }
        }

        if (failedCount > 0) {
            LOGGER.warning("Signing completed with " + failedCount + " failure(s) and " + successCount + " success(es).");
        }
        return failedCount;
    }

    private static File getOutputFile(File pdfFile, BasicConfig config) {
        String tmpNameBase = pdfFile.getName();
        String tmpSuffix = ".pdf";
        if (Strings.CI.endsWith(tmpNameBase, tmpSuffix)) {
            tmpSuffix = StringUtils.right(tmpNameBase, 4);
            tmpNameBase = StringUtils.left(tmpNameBase, tmpNameBase.length() - 4);
        }
        File outputDir = config.getOutDirectory();
        if (null == outputDir) {
            outputDir = pdfFile.getAbsoluteFile().getParentFile();
        } else {
            outputDir.mkdirs();
        }
        final StringBuilder tmpName = new StringBuilder();
        tmpName.append(tmpNameBase).append(config.getOutSuffix()).append(tmpSuffix);
        return new File(outputDir, tmpName.toString());
    }

    @SuppressWarnings("unchecked")
    private static <T> T[] asArray(T... args) {
        return args;
    }

}
