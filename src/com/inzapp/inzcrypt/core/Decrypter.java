package com.inzapp.inzcrypt.core;

import com.inzapp.inzcrypt.config.Config;

import java.io.File;

public class Decrypter {
    public boolean decrypt(File file) {
        for (int i = Config.ORDER.length - 1; i >= 0; --i) {
            switch(Config.ORDER[i]) {
                case Config.ENCODE_64:
                    break;

                case Config.ZIP_PASSWORD:
                    break;

                default:
                    break;
            }
        }
        return true;
    }
}
