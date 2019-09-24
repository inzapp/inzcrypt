package com.inzapp.inzcrypt;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class Inzcrypt {
    private Encrypter encrypter;
    private Decrypter decrypter;

    public Inzcrypt() {
        this.encrypter = new Encrypter();
        this.decrypter = new Decrypter();
    }

    public static void main(String[] args) throws Exception {
//        long startTime = System.currentTimeMillis();
//        String key = Config.KEY;
//        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
//        byte[] ivBytes = new byte[16];
//        System.arraycopy(keyBytes, 0, ivBytes, 0, 16);
//
//        System.out.println(new String(keyBytes));
//        System.out.println(new String(ivBytes));
//        System.exit(-1);
        Inzcrypt inzcrypt = new Inzcrypt();
        if (new File("1.txt").exists())
            inzcrypt.encrypt(new File("1.txt"));
        else inzcrypt.decrypt(new File("1.izc"));
    }

    public void encrypt(File file) throws Exception {
        this.encrypter.encrypt(file);
    }

    public void decrypt(File file) throws Exception {
        this.decrypter.decrypt(file);
    }
}
