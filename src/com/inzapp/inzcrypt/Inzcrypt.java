package com.inzapp.inzcrypt;

import com.inzapp.inzcrypt.exception.InvalidPasswordException;
import com.inzapp.inzcrypt.exception.PasswordIsNotRequiredException;
import com.inzapp.inzcrypt.exception.SecurityException;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
        Inzcrypt inzcrypt = Inzcrypt.load("inzcrypt.txt");
        inzcrypt.encrypt(new File("file.txt"));
//        inzcrypt.decrypt(new File("file.izc"));
        System.out.println(System.currentTimeMillis() - st);
    }

    public void addEncryptLayer(EncryptLayer encryptLayer) {
        Config.addEncryptLayer(encryptLayer);
    }

    public void setPassword(String password) throws Exception {
        if (!(password.length() == 16 || password.length() == 32))
            throw new InvalidPasswordException("password length must between 16 or 32");
        Config.setPassword(password);
    }

    public void save(String fileName) throws Exception {
        JSONObject json = new JSONObject();
        List<String> enumAttrNameList = new ArrayList<>();

        for (EncryptLayer encryptLayer : Config.getEncryptLayers())
            enumAttrNameList.add(encryptLayer.name());
        json.put(JsonKey.LAYERS.name(), enumAttrNameList);
        json.put(JsonKey.PASSWORD.name(), Config.getPassword());

        File outputFile = new File(new File("").getAbsolutePath() + "\\" + fileName);
        byte[] jsonBytes = json.toString(4).getBytes(StandardCharsets.UTF_8);
//        Inzcrypt encrypter = new Inzcrypt();
//        encrypter.addEncryptLayer(EncryptLayer.XOR);
//        jsonBytes = encrypter.encrypt(jsonBytes);
        Files.write(outputFile.toPath(), jsonBytes);
    }

    public static Inzcrypt load(String fileName) throws Exception {
        File inputFile = new File(new File("").getAbsolutePath() + "\\" + fileName);
        byte[] bytes = Files.readAllBytes(inputFile.toPath());

        JSONObject json = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        JSONArray jsonArray = json.getJSONArray(JsonKey.LAYERS.name());

        Inzcrypt inzcrypt = new Inzcrypt();
        for (int i = 0; i < jsonArray.length(); ++i)
            inzcrypt.addEncryptLayer(EncryptLayer.valueOf((String) jsonArray.get(i)));
        inzcrypt.setPassword((String) json.get(JsonKey.PASSWORD.name()));
        return inzcrypt;
    }

    public void encrypt(File file) throws Exception {
        checkException();
        this.encrypter.encrypt(file);
    }

    public void decrypt(File file) throws Exception {
        checkException();
        this.decrypter.decrypt(file);
    }

    public byte[] encrypt(byte[] bytes) throws Exception {
        checkException();
        return this.encrypter.encrypt(bytes);
    }

    public byte[] decrypt(byte[] bytes) throws Exception {
        checkException();
        return this.decrypter.decrypt(bytes);
    }

    private void checkException() throws Exception {
        if (Config.getEncryptLayers().size() == 0)
            throw new SecurityException("encrypt layers size must be over than 1");
        if (Config.checkPasswordIsInvalid())
            throw new PasswordIsNotRequiredException("no password is required for defined layers");
    }
}
