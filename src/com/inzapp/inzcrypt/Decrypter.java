package com.inzapp.inzcrypt;

import net.lingala.zip4j.core.ZipFile;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.Key;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

class Decrypter {
    private final String TMP = ".tmp";
    private final String DIR = ".dir";

    void decrypt(File file) throws Exception {
        for (int i = Config.ENCRYPT_LAYER.length - 1; i >= 0; --i) {
            switch (Config.ENCRYPT_LAYER[i]) {
                case Config.AES_128:
                case Config.AES_256:
                    aes(file);
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
        renameToOriginalName(file);
    }

    private void aes(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        ZipFile zipFile = new ZipFile(file);
        if (zipFile.isEncrypted())
            zipFile.setPassword(Config.KEY);

        File unzippedDir = new File(file.getAbsolutePath() + DIR);
        zipFile.extractFile("0", unzippedDir.getAbsolutePath());

        File unzippedZeroFile = Objects.requireNonNull(unzippedDir.listFiles())[0];
        Files.move(unzippedZeroFile.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
        Files.deleteIfExists(unzippedDir.toPath());
    }

    private byte[] aes2(byte[] bytes) throws Exception {
        List<Byte> reversedEncryptedKey = new ArrayList<>();
        for (int i = bytes.length - 1; i >= 0; --i) {
            if (bytes[i] == '\n')
                break;
            reversedEncryptedKey.add(bytes[i]);
            bytes[i] = 0;
        }

        byte[] encryptedKey = new byte[reversedEncryptedKey.size()];
        for (int r = reversedEncryptedKey.size() - 1, i = 0; r >= 0; --r, ++i)
            encryptedKey[i] = reversedEncryptedKey.get(r);

        byte[] keyBytes = decryptAESKey(encryptedKey);
        String keyStr = new String(keyBytes, StandardCharsets.UTF_8);
        String iv = keyStr.substring(0, 16);
        Key keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8)));
        return cipher.doFinal(bytes);
    }

    private byte[] decryptAESKey(byte[] plainKey) throws Exception {
        String key = Config.KEY;
        String iv = key.substring(0, 16);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        Key keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8)));
        return cipher.doFinal(plainKey);
    }

    private void des(File file) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        DESKeySpec desKeySpec = new DESKeySpec(Config.KEY.getBytes(StandardCharsets.UTF_8));
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        Key key = secretKeyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] des = Files.readAllBytes(file.toPath());
        byte[] bytes = cipher.doFinal(des);
        Files.write(file.toPath(), bytes);
    }

    private byte[] des2(byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        DESKeySpec desKeySpec = new DESKeySpec(Config.KEY.getBytes(StandardCharsets.UTF_8));
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        Key key = secretKeyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(bytes);
    }

    private void bitConversion(File file) throws Exception {
        byte[] bytes = Files.readAllBytes(file.toPath());
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = (byte) (bytes[i] ^ Config.BIT_CONVERSION_KEY);
        Files.write(file.toPath(), bytes);
    }

    private byte[] bitConversion2(byte[] bytes) {
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = (byte) (bytes[i] ^ Config.BIT_CONVERSION_KEY);
        return bytes;
    }

    private void byteMap(File file, byte[][] byteMap) throws Exception {
        byte[] bytes = Files.readAllBytes(file.toPath());
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = getFirstValeFromMap(bytes[i], byteMap);
        Files.write(file.toPath(), bytes);
    }

    private byte[] byteMap2(byte[] bytes, byte[][] byteMap) {
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

    private void base64(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        byte[] bytes = Files.readAllBytes(file.toPath());
        byte[] decodedBytes = Base64.getDecoder().decode(bytes);
        Files.write(file.toPath(), decodedBytes);
    }

    private void caesar64(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        byte[] bytes = Files.readAllBytes(file.toPath());
        for (int i = 0; i < bytes.length; ++i) {
            byte b = (byte) (((bytes[i] & 0xFF) - 64));
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

    private byte[] reverse2(byte[] bytes) {
        byte[] reversedBytes = new byte[bytes.length];
        for (int i = bytes.length - 1, r = 0; i >= 0; --i, ++r)
            reversedBytes[r] = bytes[i];
        return reversedBytes;
    }

    private void renameToOriginalName(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        byte[] bytes = Files.readAllBytes(file.toPath());
        List<Byte> reversedFileNameBytes = new ArrayList<>();
        for (int i = bytes.length - 1; i >= 0; --i) {
            if (bytes[i] == '\n')
                break;
            reversedFileNameBytes.add(bytes[i]);
            bytes[i] = 0;
        }

        byte[] fileNameBytes = new byte[reversedFileNameBytes.size()];
        for (int r = reversedFileNameBytes.size() - 1, i = 0; r >= 0; --r, ++i)
            fileNameBytes[i] = reversedFileNameBytes.get(r);

        String originalFileNameWithExtension = new String(fileNameBytes, StandardCharsets.UTF_8);
        File tmpFile = new File(file.getAbsolutePath() + TMP);
        String fileContent = new String(bytes, StandardCharsets.UTF_8)/*.trim()*/; // test for 0 byte
        Files.write(tmpFile.toPath(), fileContent.getBytes(StandardCharsets.UTF_8));

        StringBuilder originalPathBuilder = new StringBuilder();
        String[] iso = file.getAbsolutePath().split("\\\\");
        for (int i = 0; i < iso.length - 1; ++i)
            originalPathBuilder.append(iso[i]).append('\\');
        originalPathBuilder.append(originalFileNameWithExtension);
        File originalFile = new File(originalPathBuilder.toString());

        Files.deleteIfExists(file.toPath());
        Files.move(tmpFile.toPath(), originalFile.toPath());
    }
}
