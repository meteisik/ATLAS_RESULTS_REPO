import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V2_SaffronCipher {
    private String saffronCipherData;
    private static int privateFive = 5;

    private void readSaffronCipher() {
        String data = saffronCipherData;
        String saffronCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronCipherFile = new File(saffronCipherRoot + data);
            FileInputStream saffronCipherStream = null;
            InputStreamReader saffronCipherStreamReader = null;
            BufferedReader saffronCipherReader = null;
            if (saffronCipherFile.exists() && saffronCipherFile.isFile()) {
                try {
                    saffronCipherStream = new FileInputStream(saffronCipherFile);
                    saffronCipherStreamReader = new InputStreamReader(saffronCipherStream, "UTF-8");
                    saffronCipherReader = new BufferedReader(saffronCipherStreamReader);
                    System.out.println(saffronCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V2_SaffronCipher").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronCipherReader != null) {
                            saffronCipherReader.close();
                        }
                        if (saffronCipherStreamReader != null) {
                            saffronCipherStreamReader.close();
                        }
                        if (saffronCipherStream != null) {
                            saffronCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V2_SaffronCipher").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openSaffronCipher() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("SAFFRON_CIPHER_PATH");
        } else {
            data = null;
        }
        saffronCipherData = data;
        readSaffronCipher();
    }
}
