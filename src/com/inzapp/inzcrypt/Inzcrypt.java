package com.inzapp.inzcrypt;

import java.io.File;

public class Inzcrypt {
    private Encrypter encrypter;
    private Decrypter decrypter;

    public Inzcrypt() {
        this.encrypter = new Encrypter();
        this.decrypter = new Decrypter();
    }

    public static void main(String[] args) throws Exception {
//        long startTime = System.currentTimeMillis();
//        System.out.println(Encrypter.generateRandomAESKey());
//        System.out.println(System.currentTimeMillis() - startTime);
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
