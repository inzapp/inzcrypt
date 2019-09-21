package com.inzapp.inzcrypt.core;

import com.inzapp.inzcrypt.config.Config;
import net.lingala.zip4j.core.ZipFile;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

public class Decrypter {
    private final String TMP = ".tmp";
    private final String DIR = ".dir";

    public boolean decrypt(File file) throws Exception {
        for (int i = Config.ORDER.length - 1; i >= 0; --i) {
            switch (Config.ORDER[i]) {
                case Config.ENCODE_BASE64:
                    decode64(file);
                    break;

                case Config.COMPRESS_WITH_PASSWORD:
                    unZip(file);
                    break;

                default:
                    break;
            }
        }
        return renameToOriginalName(file);
    }

    private void decode64(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        BufferedReader br = new BufferedReader(new FileReader(file));
        StringBuilder sb = new StringBuilder();
        while (true) {
            String line = br.readLine();
            if (line == null)
                break;
            sb.append(line);
        }
        br.close();

        byte[] decoded = Base64.getDecoder().decode(sb.toString());
        String decodedStr = new String(decoded, StandardCharsets.UTF_8);

        FileOutputStream fos = new FileOutputStream(file.getAbsoluteFile() + TMP);
        fos.write(decodedStr.getBytes(StandardCharsets.UTF_8));
        fos.close();

        file.delete();
        new File(file.getAbsolutePath() + TMP).renameTo(file);
    }

    private void unZip(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        ZipFile zipFile = new ZipFile(file);
        if (zipFile.isEncrypted())
            zipFile.setPassword(Config.COMPRESS_PASSWORD);

        File unzippedDir = new File(file.getAbsolutePath() + DIR);
        zipFile.extractFile("0", unzippedDir.getAbsolutePath());

        File unzippedZeroFie = Objects.requireNonNull(unzippedDir.listFiles())[0];
        File tmpFile = new File(file.getAbsolutePath() + TMP);

        Files.move(unzippedZeroFie.toPath(), tmpFile.toPath());
        Files.deleteIfExists(unzippedDir.toPath());

        Files.deleteIfExists(file.toPath());
        Files.move(tmpFile.toPath(), file.toPath());
    }

    private boolean renameToOriginalName(File file) throws Exception {
        if (!file.exists())
            throw new FileNotFoundException();

        BufferedReader br = new BufferedReader(new FileReader(file));
        List<String> lines = new ArrayList<>();
        while (true) {
            String line = br.readLine();
            if (line == null)
                break;
            lines.add(line);
        }
        br.close();

        String originalFileNameWithExtension = lines.get(lines.size() - 1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.size() - 1; ++i)
            sb.append(lines.get(i)).append('\n');

        FileOutputStream fos = new FileOutputStream(file.getAbsoluteFile() + TMP);
        fos.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        fos.close();

        StringBuilder originalPathBuilder = new StringBuilder();
        String[] iso = file.getAbsolutePath().split("\\\\");
        for (int i = 0; i < iso.length - 1; ++i)
            originalPathBuilder.append(iso[i]).append('\\');
        originalPathBuilder.append(originalFileNameWithExtension);

        file.delete();
        return new File(file.getAbsolutePath() + TMP).renameTo(new File(originalPathBuilder.toString()));
    }
}
