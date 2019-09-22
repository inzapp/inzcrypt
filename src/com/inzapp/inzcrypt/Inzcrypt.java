package com.inzapp.inzcrypt;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Inzcrypt {
    private Encrypter encrypter;
    private Decrypter decrypter;

    public Inzcrypt() {
        this.encrypter = new Encrypter();
        this.decrypter = new Decrypter();
    }

    public static void main(String[] args) throws Exception {
//        List<Byte> indexes = new ArrayList<>();
//        for (int i = Byte.MIN_VALUE; i <= Byte.MAX_VALUE; ++i)
//            indexes.add((byte) i);
//
//        List<Byte> values = new ArrayList<>();
//        for (int i = Byte.MIN_VALUE; i <= Byte.MAX_VALUE; ++i)
//            values.add((byte) i);
//
//        Random random = new Random();
//        for (int i = 0; i < 1000; ++i) {
//            int randomIdx = random.nextInt(indexes.size());
//
//            byte tmp = values.get(0);
//            values.set(0, values.get(randomIdx));
//            values.set(randomIdx, tmp);
//        }
//
//        for (int i = 0; i < indexes.size(); ++i)
//            System.out.printf("{%d, %d},\n", indexes.get(i), values.get(i));
//
//        System.exit(-1);
        Inzcrypt inzcrypt = new Inzcrypt();
        inzcrypt.encrypt(new File("1.txt"));
//        inzcrypt.decrypt(new File("1.izc"));
    }

    public void encrypt(File file) throws Exception {
        this.encrypter.encrypt(file);
    }

    public void decrypt(File file) throws Exception {
        this.decrypter.decrypt(file);
    }
}
