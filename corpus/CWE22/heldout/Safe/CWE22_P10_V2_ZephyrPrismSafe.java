import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_ZephyrPrismSafe {
    public static String data;
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openZephyrPrism() {
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE22_P10_V2_ZephyrPrismSafeSink()).readZephyrPrism();
    }
}

class CWE22_P10_V2_ZephyrPrismSafeSink {
    public void readZephyrPrism() {
        String data = CWE22_P10_V2_ZephyrPrismSafe.data;
        String zephyrPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrPrismFile = new File(zephyrPrismRoot + data);
            FileInputStream zephyrPrismStream = null;
            InputStreamReader zephyrPrismStreamReader = null;
            BufferedReader zephyrPrismReader = null;
            if (zephyrPrismFile.exists() && zephyrPrismFile.isFile()) {
                try {
                    zephyrPrismStream = new FileInputStream(zephyrPrismFile);
                    zephyrPrismStreamReader = new InputStreamReader(zephyrPrismStream, "UTF-8");
                    zephyrPrismReader = new BufferedReader(zephyrPrismStreamReader);
                    System.out.println(zephyrPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_ZephyrPrismSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrPrismReader != null) {
                            zephyrPrismReader.close();
                        }
                        if (zephyrPrismStreamReader != null) {
                            zephyrPrismStreamReader.close();
                        }
                        if (zephyrPrismStream != null) {
                            zephyrPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_ZephyrPrismSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
