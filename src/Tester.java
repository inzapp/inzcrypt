import com.inzapp.inzcrypt.EncryptLayer;
import com.inzapp.inzcrypt.Inzcrypt;

import java.io.File;

class Tester {
    public static void main(String[] args) throws Exception {
        Inzcrypt inzcrypt = new Inzcrypt();
        inzcrypt.addEncryptLayer(EncryptLayer.XOR);
//        inzcrypt.setPassword("asdfasdfasdfasdf");
        inzcrypt.encrypt(new File("1.txt"));
//        inzcrypt.decrypt(new File("1.izc"));
    }
}
