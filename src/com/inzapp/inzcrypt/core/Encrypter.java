package com.inzapp.inzcrypt.core;

import com.inzapp.inzcrypt.config.Config;
import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.util.Zip4jConstants;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Encrypter {
    private final String TMP = ".tmp";

    public boolean encrypt(File file) throws Exception {
        String fileNameWithExtension = file.getName();
        String fileNameWithoutExtension = getFileNameWithoutExtension(file);
        addOriginalFileNameToLastLine(file, fileNameWithExtension);
        file = renameToZero(file);
        for (int i = 0; i < Config.ORDER.length; ++i) {
            switch (Config.ORDER[i]) {
                case Config.ENCODE_BASE64:
                    encode64(file);
                    break;

                case Config.COMPRESS_WITH_PASSWORD:
                    zip(file);
                    break;

                default:
                    break;
            }
        }
        return renameToIzcExtension(file, fileNameWithoutExtension);
    }

    private void addOriginalFileNameToLastLine(File file, String fileNameWithExtension) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        BufferedReader br = new BufferedReader(new FileReader(file));
        StringBuilder sb = new StringBuilder();
        while (true) {
            String line = br.readLine();
            if (line == null)
                break;
            sb.append(line).append('\n');
        }
        sb.append(fileNameWithExtension);
        br.close();

        FileOutputStream fos = new FileOutputStream(file.getAbsoluteFile() + TMP);
        fos.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        fos.close();

        file.delete();
        new File(file.getAbsolutePath() + TMP).renameTo(file);
    }

    private File renameToZero(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        String[] iso = file.getAbsolutePath().split("\\\\");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < iso.length - 1; ++i)
            sb.append(iso[i]).append('\\');
        sb.append(0);

        File zeroFile = new File(sb.toString());
        file.renameTo(new File(sb.toString()));
        return zeroFile;
    }

    private void encode64(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        BufferedReader br = new BufferedReader(new FileReader(file));
        StringBuilder sb = new StringBuilder();
        while (true) {
            String line = br.readLine();
            if (line == null)
                break;
            sb.append(line).append('\n');
        }
        br.close();

        byte[] base64 = Base64.getEncoder().encode(sb.toString().getBytes(StandardCharsets.UTF_8));
        String encodedFile = new String(base64, StandardCharsets.UTF_8);
        FileOutputStream fos = new FileOutputStream(file.getAbsoluteFile() + TMP);
        fos.write(encodedFile.getBytes(StandardCharsets.UTF_8));
        fos.close();

        file.delete();
        new File(file.getAbsolutePath() + TMP).renameTo(file);
    }

    private void zip(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        ZipFile zipFile = new ZipFile(file.getAbsoluteFile() + TMP);
        ZipParameters zipParameters = new ZipParameters();
        zipParameters.setCompressionMethod(Zip4jConstants.COMP_DEFLATE);
        zipParameters.setCompressionLevel(Zip4jConstants.DEFLATE_LEVEL_FASTEST);

        zipParameters.setEncryptFiles(true);
        zipParameters.setEncryptionMethod(Zip4jConstants.ENC_METHOD_AES);
        zipParameters.setAesKeyStrength(Zip4jConstants.AES_STRENGTH_256);
        zipParameters.setPassword(Config.COMPRESS_PASSWORD);
        zipFile.createZipFile(file, zipParameters);

        file.delete();
        new File(file.getAbsolutePath() + TMP).renameTo(file);
    }

    private String getFileNameWithoutExtension(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        String fileName = file.getName();
        String[] iso = fileName.split("\\.");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < iso.length - 1; ++i)
            sb.append(iso[i]);
        return sb.toString();
    }

    private boolean renameToIzcExtension(File file, String fileNameWithoutExtension) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        String[] iso = file.getAbsolutePath().split("\\\\");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < iso.length - 1; ++i)
            sb.append(iso[i]).append('\\');
        sb.append(fileNameWithoutExtension).append(".izc");
        String izcNamedPath = sb.toString();
        return file.renameTo(new File(izcNamedPath));
    }
}
