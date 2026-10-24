import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V1_GoldenCipher {

    private String locateGoldenCipher() {
        String data;
        data = System.getenv("GOLDEN_CIPHER_PATH");
        return data;
    }

    public void openGoldenCipher() {
        String data = locateGoldenCipher();
        String goldenCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenCipherFile = new File(goldenCipherRoot + data);
            FileInputStream goldenCipherStream = null;
            InputStreamReader goldenCipherStreamReader = null;
            BufferedReader goldenCipherReader = null;
            if (goldenCipherFile.exists() && goldenCipherFile.isFile()) {
                try {
                    goldenCipherStream = new FileInputStream(goldenCipherFile);
                    goldenCipherStreamReader = new InputStreamReader(goldenCipherStream, "UTF-8");
                    goldenCipherReader = new BufferedReader(goldenCipherStreamReader);
                    System.out.println(goldenCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V1_GoldenCipher").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenCipherReader != null) {
                            goldenCipherReader.close();
                        }
                        if (goldenCipherStreamReader != null) {
                            goldenCipherStreamReader.close();
                        }
                        if (goldenCipherStream != null) {
                            goldenCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V1_GoldenCipher").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
