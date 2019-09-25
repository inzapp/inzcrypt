package com.inzapp.inzcrypt;

import com.inzapp.inzcrypt.exception.InvalidPasswordException;
import com.inzapp.inzcrypt.exception.SecurityException;

import java.io.File;
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
        inzcrypt.addEncryptLayer(EncryptLayer.AES_256);
        inzcrypt.addEncryptLayer(EncryptLayer.valueOf("AES_256a"));
//        byte[] res = inzcrypt.encrypt("asd".getBytes(StandardCharsets.UTF_8));
//        byte[] bok = inzcrypt.decrypt(res);
//        System.out.println(new String(bok));
        if (new File("sample.jpg").exists())
            inzcrypt.encrypt(new File("sample.jpg"));
        else inzcrypt.decrypt(new File("sample.izc"));
        System.out.println(System.currentTimeMillis() - st);
    }

    public void addEncryptLayer(EncryptLayer encryptLayer) {
        Config.ENCRYPT_LAYERS.add(encryptLayer);
    }

    public List<EncryptLayer> getEncryptLayers() {
        return Config.ENCRYPT_LAYERS;
    }

    public void setPassword(String password) throws Exception {
        if (!(16 <= password.length() && password.length() <= 32))
            throw new InvalidPasswordException("password length must between 16 and 32");
        Config.KEY = password;
    }

    public void save(String fileName) {

    }

    public void load(String fileName) throws Exception {

    }

    public void encrypt(File file) throws Exception {
        if (Config.ENCRYPT_LAYERS.size() == 0)
            throw new SecurityException("encrypt layers size must be over than 1");
        this.encrypter.encrypt(file);
    }

    public void decrypt(File file) throws Exception {
        if (Config.ENCRYPT_LAYERS.size() == 0)
            throw new SecurityException("encrypt layers size must be over than 1");
        this.decrypter.decrypt(file);
    }

    public byte[] encrypt(byte[] bytes) throws Exception {
        if (Config.ENCRYPT_LAYERS.size() == 0)
            throw new SecurityException("encrypt layers size must be over than 1");
        return this.encrypter.encrypt(bytes);
    }

    public byte[] decrypt(byte[] encryptedBytes) throws Exception {
        if (Config.ENCRYPT_LAYERS.size() == 0)
            throw new SecurityException("encrypt layers size must be over than 1");
        return this.decrypter.decrypt(encryptedBytes);
    }
}
