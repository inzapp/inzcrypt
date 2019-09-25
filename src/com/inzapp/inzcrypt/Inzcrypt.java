package com.inzapp.inzcrypt;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

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
        if (new File("sudoku.mp4").exists())
            inzcrypt.encrypt(new File("sudoku.mp4"));
        else inzcrypt.decrypt(new File("sudoku.izc"));
        System.out.println(System.currentTimeMillis() - st);
    }

    public void addEncryptLayer(EncryptLayer encryptLayer) {
        Config.ENCRYPT_LAYERS.add(encryptLayer);
    }

    public List<EncryptLayer> getEncryptLayers() {
        return Config.ENCRYPT_LAYERS;
    }

    public void setPassword(String password) throws Exception {

    }

    public void saveConfiguration(String fileName) {

    }

    public void load(String fileName) throws Exception {

    }

    public void encrypt(File file) throws Exception {
        this.encrypter.encrypt(file);
    }

    public void decrypt(File file) throws Exception {
        this.decrypter.decrypt(file);
    }

    public byte[] encrypt(byte[] bytes) throws Exception {
        return this.encrypter.encrypt(bytes);
    }

    public byte[] decrypt(byte[] encryptedBytes) throws Exception {
        return this.decrypter.decrypt(encryptedBytes);
    }

    public String encrypt(String str) throws Exception {
        return this.encrypter.encrypt(str);
    }

    public String decrypt(String encryptedStr) throws Exception {
        return this.decrypter.decrypt(encryptedStr);
    }
}
