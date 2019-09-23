package com.inzapp.inzcrypt;

import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.util.Zip4jConstants;

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
import java.nio.file.StandardOpenOption;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;

class Encrypter {
    private final String TMP = ".tmp";

    void encrypt(File file) throws Exception {
        String fileNameWithExtension = file.getName();
        String fileNameWithoutExtension = getFileNameWithoutExtension(file);

        byte[] bytes = Files.readAllBytes(file.toPath());
        bytes = addOriginalFileNameToLastLine2(bytes, fileNameWithExtension);

//        addOriginalFileNameToLastLine(file, fileNameWithExtension);
//        file = renameToZero(file);
        for (int i = 0; i < Config.ENCRYPT_LAYER.length; ++i) {
            switch (Config.ENCRYPT_LAYER[i]) {
                case Config.AES_128:
//                    aes(file, Zip4jConstants.AES_STRENGTH_128);
                    bytes = aes2(bytes);
                    break;

                case Config.AES_256:
//                    bytes = aes2(bytes);
                    bytes = encryptAES256(bytes);
//                    aes(file, Zip4jConstants.AES_STRENGTH_256);
                    break;

                case Config.DES:
//                    des(file);
                    bytes = des2(bytes);
                    break;

                case Config.BIT_CONVERSION:
//                    bitConversion(file);
                    bytes = bitConversion2(bytes);
                    break;

                case Config.BYTE_MAP_1:
//                    byteMap(file, Config.map1);
                    bytes = byteMap2(bytes, Config.MAP_1);
                    break;

                case Config.BYTE_MAP_2:
//                    byteMap(file, Config.map2);
                    bytes = byteMap2(bytes, Config.MAP_2);
                    break;

                case Config.BYTE_MAP_3:
//                    byteMap(file, Config.map3);
                    bytes = byteMap2(bytes, Config.MAP_3);
                    break;

                case Config.BASE_64:
//                    base64(file);
                    bytes = base642(bytes);
                    break;

                case Config.CAESAR_64:
//                    caesar64(file);
                    bytes = caesar642(bytes);
                    break;

                case Config.REVERSE:
//                    reverse(file);
                    bytes = reverse2(bytes);
                    break;

                default:
                    break;
            }
        }
        Files.write(file.toPath(), bytes);
        renameToIzcExtension(file, fileNameWithoutExtension);
    }

    private void addOriginalFileNameToLastLine(File file, String fileNameWithExtension) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        Files.write(file.toPath(), ('\n' + fileNameWithExtension).getBytes(StandardCharsets.UTF_8), StandardOpenOption.APPEND);
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

    private byte[] aes2(byte[] bytes) throws Exception {
        String key = generateRandomAESKey();
        String iv = key.substring(0, 16);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        Key keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8)));

        byte[] aes = cipher.doFinal(bytes);
        List<Byte> byteList = new ArrayList<>();
        for (byte b : aes)
            byteList.add(b);
        byteList.add((byte) '\n');
        byte[] encryptedKey = encryptAESKey(keyBytes);
        encryptedKey = base642(encryptedKey);
        for (byte b : encryptedKey)
            byteList.add(b);
        bytes = new byte[byteList.size()];
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = byteList.get(i);
        return bytes;
    }

    private byte[] encryptAES256(byte[] bytes) throws Exception {
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

    private String generateRandomAESKey() {
        long seed = System.currentTimeMillis();
        Random random = new Random(seed);
        StringBuilder sb = new StringBuilder();
        char[] specials = new char[]{
                '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[',
                ';', ':', '\'', '"', ',', '<', '.', '>', '/', '?', '\\', '|', '{', ']', '}'
        };
        for (int i = 0; i < (256 / 8); ++i) {
            int rand = random.nextInt(4);
            switch (rand) {
                case 0:
                    sb.append((char) (random.nextInt('z' - 'a' + 1) + 'a'));
                    break;

                case 1:
                    sb.append((char) (random.nextInt('Z' - 'A' + 1) + 'A'));
                    break;

                case 2:
                    sb.append((char) (random.nextInt('9' - '0' + 1) + '0'));
                    break;

                case 3:
                    sb.append(specials[random.nextInt(specials.length)]);
                    break;
            }
        }
        return sb.toString();
    }

    private byte[] encryptAESKey(byte[] plainKey) throws Exception {
        String key = Config.KEY;
        String iv = key.substring(0, 16);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        Key keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8)));
        return cipher.doFinal(plainKey);
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

    private byte[] des2(byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        DESKeySpec desKeySpec = new DESKeySpec(Config.KEY.getBytes(StandardCharsets.UTF_8));
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        Key key = secretKeyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(bytes);
    }

    private void bitConversion(File file) throws Exception {
        byte[] bytes = Files.readAllBytes(file.toPath());
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = (byte) (bytes[i] ^ Config.BIT_CONVERSION_KEY);
        Files.write(file.toPath(), bytes);
    }

    private byte[] bitConversion2(byte[] bytes) throws Exception {
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = (byte) (bytes[i] ^ Config.BIT_CONVERSION_KEY);
        return bytes;
    }

    private void byteMap(File file, byte[][] byteMap) throws Exception {
        byte[] bytes = Files.readAllBytes(file.toPath());
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = getSecondValueFromMap(bytes[i], byteMap);
        Files.write(file.toPath(), bytes);
    }

    private byte[] byteMap2(byte[] bytes, byte[][] byteMap) throws Exception {
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

    private void base64(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        byte[] bytes = Files.readAllBytes(file.toPath());
        byte[] encodedBytes = Base64.getEncoder().encode(bytes);
        Files.write(file.toPath(), encodedBytes);
    }

    private byte[] base642(byte[] bytes) throws Exception {
        return Base64.getEncoder().encode(bytes);
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

    private byte[] caesar642(byte[] bytes) {
        for (int i = 0; i < bytes.length; ++i) {
            byte b = (byte) (((bytes[i] & 0xFF) + 64));
            bytes[i] = (byte) (b % 0xFF);
        }
        return bytes;
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

    private void renameToIzcExtension2(File file, String originalFileNameWithoutExtension) throws Exception {
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
