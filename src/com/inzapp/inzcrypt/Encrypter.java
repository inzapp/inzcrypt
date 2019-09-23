package com.inzapp.inzcrypt;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

class Encrypter {
    private final String TMP = ".tmp";

    void encrypt(File file) throws Exception {
        String fileNameWithExtension = file.getName();
        String fileNameWithoutExtension = getFileNameWithoutExtension(file);

        byte[] bytes = Files.readAllBytes(file.toPath());
        bytes = addOriginalFileNameToLastLine2(bytes, fileNameWithExtension);

        for (int i = 0; i < Config.ENCRYPT_LAYER.length; ++i) {
            switch (Config.ENCRYPT_LAYER[i]) {
                case Config.AES_256:
                    bytes = aes256(bytes);
                    break;

                case Config.DES:
                    bytes = des2(bytes);
                    break;

                case Config.BIT_CONVERSION:
                    bytes = bitConversion2(bytes);
                    break;

                case Config.BYTE_MAP_1:
                    bytes = byteMap2(bytes, Config.MAP_1);
                    break;

                case Config.BYTE_MAP_2:
                    bytes = byteMap2(bytes, Config.MAP_2);
                    break;

                case Config.BYTE_MAP_3:
                    bytes = byteMap2(bytes, Config.MAP_3);
                    break;

                case Config.BASE_64:
                    bytes = base642(bytes);
                    break;

                case Config.CAESAR_64:
                    bytes = caesar642(bytes);
                    break;

                case Config.REVERSE:
                    bytes = reverse2(bytes);
                    break;

                default:
                    break;
            }
        }
        Files.write(file.toPath(), bytes);
        renameToIzcExtension(file, fileNameWithoutExtension);
    }

    private byte[] addOriginalFileNameToLastLine2(byte[] bytes, String originalFileNameWithExtension) {
        List<Byte> byteList = new ArrayList<>();
        for (byte b : bytes)
            byteList.add(b);
        byte[] fileNameBytes = ('\n' + originalFileNameWithExtension).getBytes(StandardCharsets.UTF_8);
        for (byte b : fileNameBytes)
            byteList.add(b);
        bytes = new byte[byteList.size()];
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = byteList.get(i);
        return bytes;
    }

    private byte[] aes256(byte[] bytes) throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte[] saltBytes = new byte[20];
        secureRandom.nextBytes(saltBytes);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(Config.KEY.toCharArray(), saltBytes, 70000, 256);
        SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        AlgorithmParameters algorithmParameters = cipher.getParameters();

        byte[] ivBytes = algorithmParameters.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedTextBytes = cipher.doFinal(bytes);
        byte[] buffer = new byte[saltBytes.length + ivBytes.length + encryptedTextBytes.length];

        System.arraycopy(saltBytes, 0, buffer, 0, saltBytes.length);
        System.arraycopy(ivBytes, 0, buffer, saltBytes.length, ivBytes.length);
        System.arraycopy(encryptedTextBytes, 0, buffer, saltBytes.length + ivBytes.length, encryptedTextBytes.length);
        return Base64.getEncoder().encode(buffer);
    }

    private byte[] des2(byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        DESKeySpec desKeySpec = new DESKeySpec(Config.KEY.getBytes(StandardCharsets.UTF_8));
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        Key key = secretKeyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(bytes);
    }

    private byte[] bitConversion2(byte[] bytes) {
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = (byte) (bytes[i] ^ Config.BIT_CONVERSION_KEY);
        return bytes;
    }

    private byte[] byteMap2(byte[] bytes, byte[][] byteMap) {
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = getSecondValueFromMap(bytes[i], byteMap);
        return bytes;
    }

    private byte getSecondValueFromMap(byte b, byte[][] byteMap) {
        for (byte[] bytes : byteMap) {
            if (bytes[0] == b)
                return bytes[1];
        }
        return 0;
    }

    private byte[] base642(byte[] bytes) throws Exception {
        return Base64.getEncoder().encode(bytes);
    }

    private byte[] caesar642(byte[] bytes) {
        for (int i = 0; i < bytes.length; ++i) {
            byte b = (byte) (((bytes[i] & 0xFF) + 64));
            bytes[i] = (byte) (b % 0xFF);
        }
        return bytes;
    }

    private byte[] reverse2(byte[] bytes) {
        byte[] reversedBytes = new byte[bytes.length];
        for (int dec = bytes.length - 1, inc = 0; dec >= 0; --dec, ++inc)
            reversedBytes[inc] = bytes[dec];
        return reversedBytes;
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
