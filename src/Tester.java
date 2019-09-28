import com.inzapp.inzcrypt.EncryptLayer;
import com.inzapp.inzcrypt.Inzcrypt;

import java.io.File;

public class Tester {
    public static void main(String[] args) throws Exception {
        test("aes", EncryptLayer.AES, "asdfasdfasdfasdf");
        test("des", EncryptLayer.DES, "asdfasdfasdfasdf");
        test("caesar", EncryptLayer.CAESAR, null);
        test("xor", EncryptLayer.XOR, null);
        test("reverse", EncryptLayer.REVERSE, null);
        test("byte_map_1", EncryptLayer.BYTE_MAP_1, null);
        test("byte_map_2", EncryptLayer.BYTE_MAP_2, null);
        test("byte_map_3", EncryptLayer.BYTE_MAP_3, null);
    }

    private static void test(String fileNameWithoutExtension, EncryptLayer encryptLayer, String password) throws Exception {
        Inzcrypt inzcrypt = new Inzcrypt();
        inzcrypt.addEncryptLayer(encryptLayer);
        if (password != null)
            inzcrypt.setPassword(password);
        if (new File(fileNameWithoutExtension + ".txt").exists())
            inzcrypt.encrypt(new File(fileNameWithoutExtension + ".txt"));
        else inzcrypt.decrypt(new File(fileNameWithoutExtension + ".izc"));
    }
}
