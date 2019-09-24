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
        long st = System.currentTimeMillis();
        Inzcrypt inzcrypt = new Inzcrypt();
        if (new File("sample.jpg").exists())
            inzcrypt.encrypt(new File("sample.jpg"));
        else inzcrypt.decrypt(new File("sample.izc"));
        System.out.println(System.currentTimeMillis() - st);
    }

    public void encrypt(File file) throws Exception {
        this.encrypter.encrypt(file);
    }

    public void decrypt(File file) throws Exception {
        this.decrypter.decrypt(file);
    }
}
