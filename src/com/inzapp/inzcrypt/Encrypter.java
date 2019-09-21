package com.inzapp.inzcrypt;

import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.util.Zip4jConstants;

import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import java.util.List;

class Encrypter {
    private final String TMP = ".tmp";

    void encrypt(File file) throws Exception {
        String fileNameWithExtension = file.getName();
        String fileNameWithoutExtension = getFileNameWithoutExtension(file);
        addOriginalFileNameToLastLine(file, fileNameWithExtension);
        file = renameToZero(file);
        for (int i = 0; i < Config.ORDER.length; ++i) {
            switch (Config.ORDER[i]) {
                case Config.ENCODE_BASE64:
                    encode64(file);
                    break;

                case Config.REVERSE:
                    reverse(file);
                    break;

                case Config.COMPRESS:
                    zip(file);
                    break;

                default:
                    break;
            }
        }
        renameToIzcExtension(file, fileNameWithoutExtension);
    }

    private void addOriginalFileNameToLastLine(File file, String fileNameWithExtension) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        Files.write(file.toPath(), ('\n' + fileNameWithExtension).getBytes(StandardCharsets.UTF_8), StandardOpenOption.APPEND);
    }

    private File renameToZero(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        String[] iso = file.getAbsolutePath().split("\\\\");
        StringBuilder zeroNamePathBuilder = new StringBuilder();
        for (int i = 0; i < iso.length - 1; ++i)
            zeroNamePathBuilder.append(iso[i]).append('\\');
        zeroNamePathBuilder.append(0);

        File zeroFile = new File(zeroNamePathBuilder.toString());
        Files.move(file.toPath(), zeroFile.toPath());
        return zeroFile;
    }

    private void encode64(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        byte[] bytes = Files.readAllBytes(file.toPath());
        byte[] encodedBytes = Base64.getEncoder().encode(bytes);
        Files.write(file.toPath(), encodedBytes);
    }

    private void zip(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        File tmpFile = new File(file.getAbsolutePath() + TMP);
        ZipFile zipFile = new ZipFile(tmpFile);
        ZipParameters zipParameters = new ZipParameters();
        zipParameters.setCompressionMethod(Zip4jConstants.COMP_DEFLATE);
        zipParameters.setCompressionLevel(Zip4jConstants.DEFLATE_LEVEL_FASTEST);

        zipParameters.setEncryptFiles(true);
        zipParameters.setEncryptionMethod(Zip4jConstants.ENC_METHOD_AES);
        zipParameters.setAesKeyStrength(Zip4jConstants.AES_STRENGTH_256);
        zipParameters.setPassword(Config.COMPRESS_PASSWORD);
        zipFile.createZipFile(file, zipParameters);

        Files.delete(file.toPath());
        Files.move(tmpFile.toPath(), file.toPath());
    }

    private void reverse(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        byte[] bytes = Files.readAllBytes(file.toPath());
        byte[] reversedBytes = new byte[bytes.length];
        for (int i = bytes.length - 1, r = 0; i >= 0; --i, ++r)
            reversedBytes[r] = bytes[i];

        Files.write(file.toPath(), reversedBytes);
    }

    private String getFileNameWithoutExtension(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        String fileName = file.getName();
        String[] iso = fileName.split("\\.");
        StringBuilder rawFileNameBuilder = new StringBuilder();
        for (int i = 0; i < iso.length - 1; ++i)
            rawFileNameBuilder.append(iso[i]);

        return rawFileNameBuilder.toString();
    }

    private void renameToIzcExtension(File file, String originalFileNameWithoutExtension) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        String[] iso = file.getAbsolutePath().split("\\\\");
        StringBuilder izcPathBuilder = new StringBuilder();
        for (int i = 0; i < iso.length - 1; ++i)
            izcPathBuilder.append(iso[i]).append('\\');
        izcPathBuilder.append(originalFileNameWithoutExtension).append(".izc");

        File izcFile = new File(izcPathBuilder.toString());
        Files.move(file.toPath(), izcFile.toPath());
    }
}
