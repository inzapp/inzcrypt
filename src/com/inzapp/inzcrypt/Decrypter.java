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
//                    bytes = AES256Cipher.AES_Decode(bytes);
                    bytes = aes256Test(bytes);
                    break;

                case Config.DES:
//                    bytes = des(bytes);
                    bytes = des2(bytes);
                    break;

                case Config.XOR:
                    bytes = xor2(bytes);
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
        String originalName = getOriginalNameFromFileAndReplaceThemEmpty(bytes);
        bytes = new String(bytes, StandardCharsets.UTF_8).trim().getBytes(StandardCharsets.UTF_8);
        Files.write(file.toPath(), bytes);
        renameToOriginalName(file, originalName);
    }

    private byte[] aes256(byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);

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
        byte[] aesKeyBytes = decryptKeyFromLastLine(bytes);
        bytes = removeLastLine(bytes);

        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKeyBytes, "AES");
        byte[] ivBytes = new byte[16];
        System.arraycopy(aesKeyBytes, 0, ivBytes, 0, 16);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));
        return cipher.doFinal(bytes);
    }

    private byte[] decryptKeyFromLastLine(byte[] bytes) throws Exception {
        List<Byte> reversedKeyByteList = new ArrayList<>();
        for (int i = bytes.length - 1; i >= 0; --i) {
            if (bytes[i] == '\n')
                break;
            reversedKeyByteList.add(bytes[i]);
            bytes[i] = ' ';
        }
        byte[] reversedKeyBytes = new byte[reversedKeyByteList.size()];
        for (int i = 0; i < reversedKeyBytes.length; ++i)
            reversedKeyBytes[i] = reversedKeyByteList.get(i);
        byte[] encryptedKeyBytes = reverse(reversedKeyBytes);
        return decryptKey2(encryptedKeyBytes);
    }

    private byte[] removeLastLine(byte[] bytes) {
        int endIdx = 0;
        for (int i = bytes.length - 1; i >= 0; --i) {
            if (bytes[i] == '\n') {
                endIdx = i;
                break;
            }
        }
        byte[] buffer = new byte[endIdx];
        System.arraycopy(bytes, 0, buffer, 0, endIdx);
        return buffer;
    }

    private byte[] decryptKey2(byte[] encryptedKeyBytes) throws Exception {
        String keyForKey = Config.KEY;
        byte[] keyForKeyBytes = keyForKey.getBytes(StandardCharsets.UTF_8);
        byte[] ivBytes = new byte[16];
        System.arraycopy(keyForKeyBytes, 0, ivBytes, 0, 16);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyForKeyBytes, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));
        encryptedKeyBytes = base64(encryptedKeyBytes);
        return cipher.doFinal(encryptedKeyBytes);
    }

    private byte[] des2(byte[] bytes) throws Exception {
        System.out.println("before: \n" + new String(bytes, StandardCharsets.UTF_8));
        byte[] desKeyBytes = decryptKeyFromLastLine(bytes);
        bytes = removeLastLine(bytes);
        System.out.print("after: \n" + new String(bytes, StandardCharsets.UTF_8));

        Cipher cipher = Cipher.getInstance("DES");
        DESKeySpec desKeySpec = new DESKeySpec(desKeyBytes);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey =  secretKeyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(bytes);
    }

    private byte[] xor2(byte[] bytes) throws Exception {
        byte[] xorKeyBytes = decryptKeyFromLastLine(bytes);
        bytes = removeLastLine(bytes);

        ByteBuffer byteBuffer = ByteBuffer.allocate(Long.BYTES);
        byteBuffer.put(xorKeyBytes);
        byteBuffer.flip();
        long xorKey = byteBuffer.getLong();

        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = (byte) (bytes[i] ^ xorKey);
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

    private String getOriginalNameFromFileAndReplaceThemEmpty(byte[] bytes) {
        List<Byte> reversedFileNameBytes = new ArrayList<>();
        for (int i = bytes.length - 1; i >= 0; --i) {
            if (bytes[i] == '\n')
                break;
            reversedFileNameBytes.add(bytes[i]);
            bytes[i] = ' '; // change bytes references value
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
