import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_GoldenCipher {
    private static boolean privateTrue = true;

    public void openGoldenCipher() {
        String data;
        if (privateTrue) {
            data = System.getenv("GOLDEN_CIPHER_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_GoldenCipherBase baseObject = new CWE22_P12_V2_GoldenCipherSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_GoldenCipherBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_GoldenCipherSink extends CWE22_P12_V2_GoldenCipherBase {
    public void action(String data) {
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
                    Logger.getLogger("CWE22_P12_V2_GoldenCipherSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V2_GoldenCipherSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
