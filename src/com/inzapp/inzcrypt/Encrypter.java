package com.inzapp.inzcrypt;

import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.util.Zip4jConstants;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.util.Base64;

class Encrypter {
    private final String TMP = ".tmp";

    void encrypt(File file) throws Exception {
        String fileNameWithExtension = file.getName();
        String fileNameWithoutExtension = getFileNameWithoutExtension(file);
        addOriginalFileNameToLastLine(file, fileNameWithExtension);
        file = renameToZero(file);
        for (int i = 0; i < Config.ENCRYPT_LAYER.length; ++i) {
            switch (Config.ENCRYPT_LAYER[i]) {
                case Config.AES_128:
                    aes(file, Zip4jConstants.AES_STRENGTH_128);
                    break;

                case Config.AES_256:
                    aes(file, Zip4jConstants.AES_STRENGTH_256);
                    break;

                case Config.DES:
                    des(file);
                    break;

                case Config.BIT_CONVERSION:
                    bitConversion(file);
                    break;

                case Config.BYTE_MAP_1:
                    byteMap(file, Config.map1);
                    break;

                case Config.BYTE_MAP_2:
                    byteMap(file, Config.map2);
                    break;

                case Config.BYTE_MAP_3:
                    byteMap(file, Config.map3);
                    break;

                case Config.BASE_64:
                    base64(file);
                    break;

                case Config.CAESAR_64:
                    caesar64(file);
                    break;

                case Config.REVERSE:
                    reverse(file);
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

    private void aes(File file, int aesStrength) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        File tmpFile = new File(file.getAbsolutePath() + TMP);
        ZipFile zipFile = new ZipFile(tmpFile);
        ZipParameters zipParameters = new ZipParameters();
        zipParameters.setCompressionMethod(Zip4jConstants.COMP_DEFLATE);
        zipParameters.setCompressionLevel(Zip4jConstants.DEFLATE_LEVEL_FASTEST);

        zipParameters.setEncryptFiles(true);
        zipParameters.setEncryptionMethod(Zip4jConstants.ENC_METHOD_AES);
        zipParameters.setAesKeyStrength(aesStrength);
        zipParameters.setPassword(Config.KEY);
        zipFile.createZipFile(file, zipParameters);

        Files.delete(file.toPath());
        Files.move(tmpFile.toPath(), file.toPath());
    }

    private void des(File file) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        DESKeySpec desKeySpec = new DESKeySpec(Config.KEY.getBytes(StandardCharsets.UTF_8));
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        Key key = secretKeyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = Files.readAllBytes(file.toPath());
        byte[] des = cipher.doFinal(bytes);
        Files.write(file.toPath(), des);
    }

    private void bitConversion(File file) throws Exception {
        byte[] bytes = Files.readAllBytes(file.toPath());
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = (byte) (bytes[i] ^ Config.BIT_CONVERSION_KEY);
        Files.write(file.toPath(), bytes);
    }

    private void byteMap(File file, byte[][] byteMap) throws Exception {
        byte[] bytes = Files.readAllBytes(file.toPath());
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = getSecondValueFromMap(bytes[i], byteMap);
        Files.write(file.toPath(), bytes);
    }

    private byte getSecondValueFromMap(byte b, byte[][] byteMap) {
        for (byte[] bytes : byteMap) {
            if (bytes[0] == b)
                return bytes[1];
        }
        return Byte.MAX_VALUE;
    }

    private void base64(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        byte[] bytes = Files.readAllBytes(file.toPath());
        byte[] encodedBytes = Base64.getEncoder().encode(bytes);
        Files.write(file.toPath(), encodedBytes);
    }

    private void caesar64(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        byte[] bytes = Files.readAllBytes(file.toPath());
        for (int i = 0; i < bytes.length; ++i) {
            byte b = (byte) (((bytes[i] & 0xFF) + 64));
            bytes[i] = (byte) (b % 0xFF);
        }
        Files.write(file.toPath(), bytes);
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
