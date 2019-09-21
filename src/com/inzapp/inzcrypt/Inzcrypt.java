package com.inzapp.inzcrypt;

import com.inzapp.inzcrypt.core.Decrypter;
import com.inzapp.inzcrypt.core.Encrypter;

import java.io.File;

public class Inzcrypt {
    public static void main(String[] args) {
        Inzcrypt inzcrypt = new Inzcrypt();
        try {
            if (inzcrypt.encrypt(new File("1.iml")))
                System.out.println("encrypt success");
            else System.out.println("encrypt failure");


            if (inzcrypt.decrypt(new File("1.izc")))
                System.out.println("decrypt success");
            else System.out.println("decrypt failure");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean encrypt(File file) throws Exception {
        return new Encrypter().encrypt(file);
    }

    public boolean decrypt(File file) throws Exception {
        return new Decrypter().decrypt(file);
    }
}
