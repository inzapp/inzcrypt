package com.inzapp.inzcrypt;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Key;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

class Decrypter {
    void decrypt(File file) throws Exception {
        byte[] bytes = Files.readAllBytes(file.toPath());
        for (int i = Config.ENCRYPT_LAYER.length - 1; i >= 0; --i) {
            switch (Config.ENCRYPT_LAYER[i]) {
                case Config.AES_256:
//                    bytes = aes256(bytes);
                    bytes = aes256Test(bytes);
                    break;

                case Config.DES:
                    bytes = des(bytes);
                    break;

                case Config.BIT_CONVERSION:
                    bytes = bitConversion(bytes);
                    break;

                case Config.BYTE_MAP_1:
                    bytes = byteMap(bytes, Config.MAP_1);
                    break;

                case Config.BYTE_MAP_2:
                    bytes = byteMap(bytes, Config.MAP_2);
                    break;

                case Config.BYTE_MAP_3:
                    bytes = byteMap(bytes, Config.MAP_3);
                    break;

                case Config.BASE_64:
                    bytes = base64(bytes);
                    break;

                case Config.CAESAR_64:
                    bytes = caesar64(bytes);
                    break;

                case Config.REVERSE:
                    bytes = reverse(bytes);
                    break;

                default:
                    break;
            }
        }
        String originalName = getOriginalNameFromFileAndReplaceThemToZero(bytes);
        bytes = new String(bytes, StandardCharsets.UTF_8).trim().getBytes(StandardCharsets.UTF_8);
        Files.write(file.toPath(), bytes);
        renameToOriginalName(file, originalName);
    }

    private byte[] aes256(byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ByteBuffer byteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(bytes));

        byte[] saltBytes = new byte[20];
        byteBuffer.get(saltBytes, 0, saltBytes.length);
        byte[] ivBytes = new byte[cipher.getBlockSize()];
        byteBuffer.get(ivBytes, 0, ivBytes.length);
        byte[] encryptedTextBytes = new byte[byteBuffer.capacity() - saltBytes.length - ivBytes.length];
        byteBuffer.get(encryptedTextBytes);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(Config.KEY.toCharArray(), saltBytes, 64, 256);

        SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));
        return cipher.doFinal(encryptedTextBytes);
    }

    private byte[] aes256Test(byte[] bytes) throws Exception {
        String encryptedKey = getEncryptedKeyFromLastLine(bytes);
        bytes = removeLastLine(bytes);
        System.out.println(new String(bytes, StandardCharsets.UTF_8));
        String decryptedKey = decryptKey(encryptedKey);

        byte[] decryptedKeyBytes = decryptedKey.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(decryptedKeyBytes, "AES");

        String iv = decryptedKey.substring(0, 16);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(bytes);
    }

    private String getEncryptedKeyFromLastLine(byte[] bytes) {
        List<Byte> reversedByteList = new ArrayList<>();
        for (int i = bytes.length - 1; i >= 0; --i) {
            if (bytes[i] == '\n') {
                bytes[i] = ' ';
                break;
            }
            reversedByteList.add(bytes[i]);
            bytes[i] = ' ';
        }
        byte[] encryptedKeyBytes = new byte[reversedByteList.size()];
        for (int dec = reversedByteList.size() - 1, inc = 0; dec >= 0; --dec, ++inc)
            encryptedKeyBytes[inc] = reversedByteList.get(dec);
        return new String(encryptedKeyBytes, StandardCharsets.UTF_8);
    }

    private byte[] removeLastLine(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8).trim().getBytes(StandardCharsets.UTF_8);
    }

    private String decryptKey(String encryptedKey) throws Exception {
        String key = Config.KEY;
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        String iv = key.substring(0, 16);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        System.out.println(encryptedKey); // TODO
        byte[] encryptedKeyBytes = encryptedKey.getBytes(StandardCharsets.UTF_8);
        encryptedKeyBytes = base64(encryptedKeyBytes);
        System.out.println(new String(encryptedKeyBytes)); // TODO
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKeyBytes);
        return new String(decryptedKeyBytes, StandardCharsets.UTF_8);
    }

    private byte[] des(byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        DESKeySpec desKeySpec = new DESKeySpec(Config.KEY.getBytes(StandardCharsets.UTF_8));
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        Key key = secretKeyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(bytes);
    }

    private byte[] bitConversion(byte[] bytes) {
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = (byte) (bytes[i] ^ Config.BIT_CONVERSION_KEY);
        return bytes;
    }

    private byte[] byteMap(byte[] bytes, byte[][] byteMap) {
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = getFirstValeFromMap(bytes[i], byteMap);
        return bytes;
    }

    private byte getFirstValeFromMap(byte b, byte[][] byteMap) {
        for (byte[] bytes : byteMap) {
            if (bytes[1] == b)
                return bytes[0];
        }
        return 0;
    }

    private byte[] base64(byte[] bytes) {
        return Base64.getDecoder().decode(bytes);
    }

    private byte[] caesar64(byte[] bytes) {
        for (int i = 0; i < bytes.length; ++i) {
            byte b = (byte) (((bytes[i] & 0xFF) - 64));
            bytes[i] = (byte) (b % 0xFF);
        }
        return bytes;
    }

    private byte[] reverse(byte[] bytes) {
        byte[] reversedBytes = new byte[bytes.length];
        for (int dec = bytes.length - 1, inc = 0; dec >= 0; --dec, ++inc)
            reversedBytes[inc] = bytes[dec];
        return reversedBytes;
    }

    private String getOriginalNameFromFileAndReplaceThemToZero(byte[] bytes) {
        List<Byte> reversedFileNameBytes = new ArrayList<>();
        for (int i = bytes.length - 1; i >= 0; --i) {
            if (bytes[i] == '\n')
                break;
            reversedFileNameBytes.add(bytes[i]);
            bytes[i] = 0; // change bytes references value
        }
        byte[] fileNameBytes = new byte[reversedFileNameBytes.size()];
        for (int dec = reversedFileNameBytes.size() - 1, inc = 0; dec >= 0; --dec, ++inc)
            fileNameBytes[inc] = reversedFileNameBytes.get(dec);
        return new String(fileNameBytes, StandardCharsets.UTF_8);
    }

    private void renameToOriginalName(File file, String originalFileName) throws IOException {
        StringBuilder originalPathBuilder = new StringBuilder();
        String[] iso = file.getAbsolutePath().split("\\\\");
        for (int i = 0; i < iso.length - 1; ++i)
            originalPathBuilder.append(iso[i]).append('\\');
        originalPathBuilder.append(originalFileName);
        File originalFile = new File(originalPathBuilder.toString());
        Files.move(file.toPath(), originalFile.toPath());
    }
}
