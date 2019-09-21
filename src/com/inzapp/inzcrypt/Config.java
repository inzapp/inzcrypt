package com.inzapp.inzcrypt;

class Config {
    static final String AES_KEY = "AES_KEY_QUVTX0tFWV8xOTIzODczODkzODc0";
    static final String AES_128 = "AES_128";
    static final String AES_256 = "AES_256";
    static final String BASE_64 = "BASE_64";
    static final String REVERSE = "REVERSE";
    static final String[] ORDER = new String[]{
            AES_256,
            AES_128,
            REVERSE,
            BASE_64,
            AES_256,
            REVERSE
    };
}
