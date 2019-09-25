package com.inzapp.inzcrypt;

public enum EncryptLayer {
    AES_256("AES_256"),
    DES("DES"),
    CAESAR("CAESAR"),
    XOR("XOR"),
    BASE_64("BASE_64"),
    REVERSE("REVERSE"),
    BYTE_MAP_1("BYTE_MAP_1"),
    BYTE_MAP_2("BYTE_MAP_2"),
    BYTE_MAP_3("BYTE_MAP_3");

    EncryptLayer(String s) {
    }
}
