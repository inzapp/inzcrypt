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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;


class AES256Cipher {
    private static volatile AES256Cipher INSTANCE;
    private static final String secretKey = "Q!d$2018072316543418070119376805"; //32bit
    //    static String IV = "L$b@180701193768"; //16bit
    static String IV = "Q!d$201807231654";

    public static AES256Cipher getInstance() {
        if (INSTANCE == null) {
            synchronized (AES256Cipher.class) {
                if (INSTANCE == null)
                    INSTANCE = new AES256Cipher();
            }
        }
        return INSTANCE;
    }

    private AES256Cipher() {
        IV = secretKey.substring(0, 16);
    }

    // Encryption
    public static byte[] AES_Encode(byte[] bytes) throws Exception {
//        byte[] keyData = secretKey.getBytes();
        byte[] keyBytes = Config.KEY.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(IV.getBytes()));
        return c.doFinal(bytes);
    }

    // Decryption
    public static byte[] AES_Decode(byte[] bytes) throws Exception {
//        byte[] keyData = secretKey.getBytes();
        byte[] keyBytes = Config.KEY.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8)));
        return c.doFinal(bytes);
    }
}

class Encrypter {
    void encrypt(File file) throws Exception {
        String fileNameWithExtension = file.getName();
        String fileNameWithoutExtension = getFileNameWithoutExtension(file);

        byte[] bytes = Files.readAllBytes(file.toPath());
        System.out.println("saving file name : " + fileNameWithExtension);
        bytes = addOriginalFileNameToLastLine(bytes, fileNameWithExtension);

        for (int i = 0; i < Config.ENCRYPT_LAYER.length; ++i) {
            switch (Config.ENCRYPT_LAYER[i]) {
                case Config.AES_256:
                    bytes = aes256Test(bytes);
                    break;

                case Config.DES:
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
//                    bytes = caesar64(bytes);
//                    bytes = caesar222(bytes);
                    bytes = caesar2223(bytes);
                    break;

                case Config.REVERSE:
                    bytes = reverse(bytes);
                    break;

                default:
                    break;
            }
        }
        Files.write(file.toPath(), bytes);
        renameToIzcExtension(file, fileNameWithoutExtension);
    }

    private byte[] addOriginalFileNameToLastLine(byte[] bytes, String originalFileNameWithExtension) {
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

    private byte[] aes256WithSha1(byte[] bytes) throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte[] saltBytes = new byte[20];
        secureRandom.nextBytes(saltBytes);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(Config.KEY.toCharArray(), saltBytes, 64, 256);
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
        return buffer;
    }

    private byte[] aes256Test(byte[] bytes) throws Exception {
        String aesKey = generateRandomKey();
        byte[] aesKeyBytes = aesKey.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKeyBytes, "AES");

        byte[] ivBytes = new byte[16];
        System.arraycopy(aesKeyBytes, 0, ivBytes, 0, 16);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));

        bytes = cipher.doFinal(bytes);
        return appendNewLineAsEncrypted(bytes, aesKeyBytes);
    }

    private String generateRandomKey() {
        StringBuilder sb = new StringBuilder();
        Random random = new Random(System.currentTimeMillis());
        char[] specials = new char[]{
                '`', '~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+',
                '[', '{', ']', '}', '\\', '|', ';', ':', '\'', '"', ',', '<', '.', '>', '/', '?'
        };
        for (int i = 0; i < 256 / 8; ++i) { // 256 bit key
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

                default:
                    break;
            }
        }
        return sb.toString();
    }

    private byte[] encryptKey(byte[] plainKeyBytes) throws Exception {
        String keyForKey = Config.KEY;
        byte[] keyForKeyBytes = keyForKey.getBytes(StandardCharsets.UTF_8);
        byte[] ivBytes = new byte[16];
        System.arraycopy(keyForKeyBytes, 0, ivBytes, 0, 16);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyForKeyBytes, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));
        return cipher.doFinal(plainKeyBytes);
    }

    private byte[] des2(byte[] bytes) throws Exception {
        String desKey = generateRandomKey();
        byte[] desKeyBytes = desKey.getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance("DES");
        DESKeySpec desKeySpec = new DESKeySpec(desKeyBytes);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        bytes = cipher.doFinal(bytes);
        return appendNewLineAsEncrypted(bytes, desKeyBytes);
    }

    private byte[] xor2(byte[] bytes) throws Exception {
        long xorKey = new Random().nextLong();
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = (byte) (bytes[i] ^ xorKey);

        ByteBuffer byteBuffer = ByteBuffer.allocate(Long.BYTES);
        byteBuffer.putLong(xorKey);
        byte[] xorKeyBytes = byteBuffer.array();
        return appendNewLineAsEncrypted(bytes, xorKeyBytes);
    }

    private byte[] byteMap(byte[] bytes, byte[][] byteMap) {
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

    private byte[] base64(byte[] bytes) {
        return Base64.getEncoder().encode(bytes);
    }

    private byte[] caesar64(byte[] bytes) {
        for (int i = 0; i < bytes.length; ++i) {
            byte b = (byte) (((bytes[i] & 0xFF) + 64));
            bytes[i] = (byte) (b % 0xFF);
        }
        return bytes;
    }

    private byte[] caesar222(byte[] bytes) throws Exception {
        byte[] caesarKeyBuffer = new byte[32];
        new Random().nextBytes(caesarKeyBuffer);
        byte caesarKey = caesarKeyBuffer[7];
        for (int i = 0; i < bytes.length; ++i) {
            byte b = (byte) (((bytes[i] & 0xFF) + caesarKey));
            bytes[i] = (byte) (b % 0xFF);
        }
        return appendNewLineAsEncrypted(bytes, caesarKeyBuffer);
    }

    private byte[] caesar2223(byte[] bytes) throws Exception {
        String caesarKey = generateRandomKey();
        byte[] caesarKeyBuffer = caesarKey.getBytes(StandardCharsets.UTF_8);
        byte realCaesarKey = caesarKeyBuffer[7];
        for (int i = 0; i < bytes.length; ++i) {
            byte b = (byte) (((bytes[i] & 0xFF) + realCaesarKey));
            bytes[i] = (byte) (b % 0xFF);
        }
        return appendNewLineAsEncrypted(bytes, caesarKeyBuffer);
    }

    private byte[] appendNewLineAsEncrypted(byte[] bytes, byte[] appendBytes) throws Exception {
        appendBytes = encryptKey(appendBytes);
        appendBytes = base64(appendBytes);
        byte[] newLine = new byte[]{'\n'};
        byte[] buffer = new byte[bytes.length + newLine.length + appendBytes.length];
        System.arraycopy(bytes, 0, buffer, 0, bytes.length);
        System.arraycopy(newLine, 0, buffer, bytes.length, newLine.length);
        System.arraycopy(appendBytes, 0, buffer, bytes.length + newLine.length, appendBytes.length);
        return buffer;
    }

    private byte[] reverse(byte[] bytes) {
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
