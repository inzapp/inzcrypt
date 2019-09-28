import com.inzapp.inzcrypt.Inzcrypt;

import java.io.File;

class Tester {
    public static void main(String[] args) throws Exception {
        Inzcrypt inzcrypt = Inzcrypt.load("key.txt");

        String fileName = "1";
        File txtFile = new File(fileName + ".txt");
        if (txtFile.exists())
            inzcrypt.encrypt(txtFile);
        else inzcrypt.decrypt(new File(fileName + ".izc"));
    }
}
