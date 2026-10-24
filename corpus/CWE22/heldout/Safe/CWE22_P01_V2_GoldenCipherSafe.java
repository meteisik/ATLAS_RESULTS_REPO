import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V2_GoldenCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openGoldenCipher() {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
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
                    Logger.getLogger("CWE22_P01_V2_GoldenCipherSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P01_V2_GoldenCipherSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
