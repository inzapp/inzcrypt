package com.inzapp.inzcrypt;

import net.lingala.zip4j.core.ZipFile;

import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

class Decrypter {
    private final String TMP = ".tmp";
    private final String DIR = ".dir";

    void decrypt(File file) throws Exception {
        for (int i = Config.ORDER.length - 1; i >= 0; --i) {
            switch (Config.ORDER[i]) {
                case Config.AES_128:
                case Config.AES_256:
                    decryptAes(file);
                    break;

                case Config.BASE_64:
                    decode64(file);
                    break;

                case Config.CAESAR_64:
                    caesar64(file);

                case Config.REVERSE:
                    reverse(file);
                    break;

                default:
                    break;
            }
        }
        renameToOriginalName(file);
    }

    private void decryptAes(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        ZipFile zipFile = new ZipFile(file);
        if (zipFile.isEncrypted())
            zipFile.setPassword(Config.AES_KEY);

        File unzippedDir = new File(file.getAbsolutePath() + DIR);
        zipFile.extractFile("0", unzippedDir.getAbsolutePath());

        File unzippedZeroFile = Objects.requireNonNull(unzippedDir.listFiles())[0];
        Files.move(unzippedZeroFile.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
        Files.deleteIfExists(unzippedDir.toPath());
    }

    private void decode64(File file) throws Exception {
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

    private void renameToOriginalName(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        byte[] fileBytes = Files.readAllBytes(file.toPath());
        List<Byte> reversedFileNameBytes = new ArrayList<>();
        for (int i = fileBytes.length - 1; i >= 0; --i) {
            if (fileBytes[i] == '\n')
                break;
            reversedFileNameBytes.add(fileBytes[i]);
            fileBytes[i] = ' ';
        }

        byte[] fileNameBytes = new byte[reversedFileNameBytes.size()];
        for (int r = reversedFileNameBytes.size() - 1, i = 0; r >= 0; --r, ++i)
            fileNameBytes[i] = reversedFileNameBytes.get(r);

        String originalFileNameWithExtension = new String(fileNameBytes, StandardCharsets.UTF_8);

        File tmpFile = new File(file.getAbsolutePath() + TMP);
        String fileContent = new String(fileBytes, StandardCharsets.UTF_8).trim();
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
