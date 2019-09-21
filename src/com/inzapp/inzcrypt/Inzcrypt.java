package com.inzapp.inzcrypt;

import com.inzapp.inzcrypt.core.Decrypter;
import com.inzapp.inzcrypt.core.Encrypter;

import java.io.File;

public class Inzcrypt {
    private Encrypter encrypter;
    private Decrypter decrypter;

    public Inzcrypt() {
        this.encrypter = new Encrypter();
        this.decrypter = new Decrypter();
    }

    public static void main(String[] args) throws Exception {
        Inzcrypt inzcrypt = new Inzcrypt();
        inzcrypt.encrypt(new File("1.iml"));
        inzcrypt.decrypt(new File("1.izc"));
    }

    public void encrypt(File file) throws Exception {
        this.encrypter.encrypt(file);
    }

    public void decrypt(File file) throws Exception {
        this.decrypter.decrypt(file);
    }
}
