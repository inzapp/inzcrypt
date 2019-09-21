package com.inzapp.inzcrypt;

import com.inzapp.inzcrypt.core.Encrypter;

import java.io.File;

public class Inzcrypt {
    public static void main(String[] args) {
        Inzcrypt inzcrypt = new Inzcrypt();
        try {
            if (inzcrypt.encrypt(new File("test.xml")))
                System.out.println("encrypt success");
            else System.out.println("encrypt failure");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean encrypt(File file) throws Exception {
        return new Encrypter().encrypt(file);
    }
}
