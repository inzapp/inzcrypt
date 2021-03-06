package com.inzapp.inzcrypt;

import com.inzapp.inzcrypt.exception.WrongPasswordException;

import javax.crypto.BadPaddingException;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

class Decrypter {
    private Config config;

    Decrypter(Config config) {
        this.config = config;
    }

    void decrypt(File file) throws Exception {
        byte[] bytes = Files.readAllBytes(file.toPath());
        bytes = decrypt(bytes);
        String originalName = getOriginalNameFromFileAndReplaceThemEmpty(bytes);
        bytes = removeLastLine(bytes);
        Files.write(file.toPath(), bytes);
        renameToOriginalName(file, originalName);
    }

    byte[] decrypt(byte[] bytes) throws Exception {
        for (int i = this.config.getEncryptLayers().size() - 1; i >= 0; --i) {
            switch (this.config.getEncryptLayers().get(i)) {
                case AES:
                    bytes = aes(bytes);
                    break;

                case DES:
                    bytes = des(bytes);
                    break;

                case XOR:
                    bytes = xor(bytes);
                    break;

                case CAESAR:
                    bytes = caesar(bytes);
                    break;

                case REVERSE:
                    bytes = reverse(bytes);
                    break;

                case BYTE_MAP_1:
                    bytes = byteMap(bytes, this.config.MAP_1);
                    break;

                case BYTE_MAP_2:
                    bytes = byteMap(bytes, this.config.MAP_2);
                    break;

                case BYTE_MAP_3:
                    bytes = byteMap(bytes, this.config.MAP_3);
                    break;

                default:
                    break;
            }
        }
        return bytes;
    }

    private byte[] aes256WithSha1(byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);

        byte[] saltBytes = new byte[20];
        byteBuffer.get(saltBytes, 0, saltBytes.length);

        byte[] ivBytes = new byte[cipher.getBlockSize()];
        byteBuffer.get(ivBytes, 0, ivBytes.length);

        byte[] encryptedTextBytes = new byte[byteBuffer.capacity() - saltBytes.length - ivBytes.length];
        byteBuffer.get(encryptedTextBytes);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec pbeKeySpec = new PBEKeySpec(this.config.getPassword().toCharArray(), saltBytes, 64, 256);
        SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));
        return cipher.doFinal(encryptedTextBytes);
    }

    private byte[] aes(byte[] bytes) throws Exception {
        byte[] aesKeyBytes = decryptKeyFromLastLine(bytes);
        bytes = removeLastLine(bytes);
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKeyBytes, "AES");

        byte[] ivBytes = new byte[16];
        System.arraycopy(aesKeyBytes, 0, ivBytes, 0, 16);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));
        return cipher.doFinal(bytes);
    }

    private byte[] des(byte[] bytes) throws Exception {
        byte[] desKeyBytes = decryptKeyFromLastLine(bytes);
        bytes = removeLastLine(bytes);

        DESKeySpec desKeySpec = new DESKeySpec(desKeyBytes);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);

        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(bytes);
    }

    private byte[] xor(byte[] bytes) throws Exception {
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

    private byte[] caesar(byte[] bytes) throws Exception {
        byte[] caesarKeyBytes = decryptKeyFromLastLine(bytes);
        bytes = removeLastLine(bytes);

        byte realCaesarKey = caesarKeyBytes[7];
        for (int i = 0; i < bytes.length; ++i) {
            byte b = (byte) (((bytes[i] & 0xFF) - realCaesarKey));
            bytes[i] = (byte) (b % 0xFF);
        }
        return bytes;
    }

    private byte[] base64(byte[] bytes) {
        return Base64.getDecoder().decode(bytes);
    }

    private byte[] reverse(byte[] bytes) {
        byte[] reversedBytes = new byte[bytes.length];
        for (int dec = bytes.length - 1, inc = 0; dec >= 0; --dec, ++inc)
            reversedBytes[inc] = bytes[dec];
        return reversedBytes;
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
        return decryptKey(encryptedKeyBytes);
    }

    private byte[] decryptKey(byte[] encryptedKeyBytes) throws Exception {
        String keyForKey = this.config.getPassword();
        byte[] keyForKeyBytes = keyForKey.getBytes(StandardCharsets.UTF_8);

        byte[] ivBytes = new byte[16];
        System.arraycopy(keyForKeyBytes, 0, ivBytes, 0, 16);

        SecretKeySpec secretKeySpec = new SecretKeySpec(keyForKeyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivBytes));

        encryptedKeyBytes = base64(encryptedKeyBytes);
        try {
            return cipher.doFinal(encryptedKeyBytes);
        } catch (BadPaddingException e) {
            throw new WrongPasswordException("password is wrong");
        }
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

    private String getOriginalNameFromFileAndReplaceThemEmpty(byte[] bytes) {
        List<Byte> reversedFileNameByteList = new ArrayList<>();
        for (int i = bytes.length - 1; i >= 0; --i) {
            if (bytes[i] == '\n')
                break;
            reversedFileNameByteList.add(bytes[i]);
            bytes[i] = ' '; // change bytes references value
        }
        byte[] reversedFileNameBytes = new byte[reversedFileNameByteList.size()];
        for (int dec = reversedFileNameByteList.size() - 1, inc = 0; dec >= 0; --dec, ++inc)
            reversedFileNameBytes[inc] = reversedFileNameByteList.get(dec);
        return new String(reversedFileNameBytes, StandardCharsets.UTF_8);
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
