package com.inzapp.inzcrypt;

import com.inzapp.inzcrypt.exception.InvalidPasswordException;
import com.inzapp.inzcrypt.exception.PasswordException;
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
    private Config config;

    public Inzcrypt() {
        this.config = new Config();
        this.encrypter = new Encrypter(config);
        this.decrypter = new Decrypter(config);
    }

/*    public static void main(String[] args) throws Exception {
        test("aes", EncryptLayer.AES, "asdfasdfasdfasdf");
        test("des", EncryptLayer.DES, "asdfasdfasdfasdf");
        test("caesar", EncryptLayer.CAESAR, "asdfasdfasdfasdf");
        test("xor", EncryptLayer.XOR, "asdfasdfasdfasdf");
        test("reverse", EncryptLayer.REVERSE, "asdfasdfasdfasdf");
        test("byte_map_1", EncryptLayer.BYTE_MAP_1, "asdfasdfasdfasdf");
        test("byte_map_2", EncryptLayer.BYTE_MAP_2, "asdfasdfasdfasdf");
        test("byte_map_3", EncryptLayer.BYTE_MAP_3, "asdfasdfasdfasdf");
    }

    private static void test(String fileNameWithoutExtension, EncryptLayer encryptLayer, String password) throws Exception {
        Inzcrypt inzcrypt = new Inzcrypt();
        inzcrypt.addEncryptLayer(encryptLayer);
        System.out.println(this.config.getEncryptLayers().size());
        if(password != null)
            inzcrypt.setPassword(password);
        if(new File(fileNameWithoutExtension + ".txt").exists())
            inzcrypt.encrypt(new File(fileNameWithoutExtension + ".txt"));
        else inzcrypt.decrypt(new File(fileNameWithoutExtension + ".izc"));
    }*/

    public void addEncryptLayer(EncryptLayer encryptLayer) {
        this.config.addEncryptLayer(encryptLayer);
    }

    public void setPassword(String password) throws Exception {
        if (!(password.length() == 16 || password.length() == 32))
            throw new InvalidPasswordException("password length must be 16 or 32");
        this.config.setPassword(password);
    }

    public void save(String fileName) throws Exception {
        JSONObject json = new JSONObject();
        List<String> enumAttrNameList = new ArrayList<>();

        for (EncryptLayer encryptLayer : this.config.getEncryptLayers())
            enumAttrNameList.add(encryptLayer.name());
        json.put(JsonKey.LAYERS.name(), enumAttrNameList);
        json.put(JsonKey.PASSWORD.name(), this.config.getPassword());

        File outputFile = new File(new File("").getAbsolutePath() + "\\" + fileName);
        byte[] jsonBytes = json.toString(4).getBytes(StandardCharsets.UTF_8);
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
        if (this.config.getEncryptLayers().size() == 0)
            throw new SecurityException("encrypt layers size must be over than 1");
        if (!this.config.checkRequirePassword() && this.config.checkPasswordIsChanged())
            throw new PasswordException("password is not required. defined layer is substitution cipher algorithm. it will be encrypted by random generated key.");
        if (this.config.checkRequirePassword() && !this.config.checkPasswordIsChanged())
            throw new PasswordException("password is required. defined layer is symmetric-key algorithm layer. symmetric-key algorithm layer :  " + this.config.passwordRequiredLayersToString() + ".");
    }
}
