import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_ZephyrGlint {
    public static String data;
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openZephyrGlint() {
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ZEPHYR_GLINT_PATH");
        } else {
            data = null;
        }
        (new CWE22_P10_V2_ZephyrGlintSink()).readZephyrGlint();
    }
}

class CWE22_P10_V2_ZephyrGlintSink {
    public void readZephyrGlint() {
        String data = CWE22_P10_V2_ZephyrGlint.data;
        String zephyrGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrGlintFile = new File(zephyrGlintRoot + data);
            FileInputStream zephyrGlintStream = null;
            InputStreamReader zephyrGlintStreamReader = null;
            BufferedReader zephyrGlintReader = null;
            if (zephyrGlintFile.exists() && zephyrGlintFile.isFile()) {
                try {
                    zephyrGlintStream = new FileInputStream(zephyrGlintFile);
                    zephyrGlintStreamReader = new InputStreamReader(zephyrGlintStream, "UTF-8");
                    zephyrGlintReader = new BufferedReader(zephyrGlintStreamReader);
                    System.out.println(zephyrGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_ZephyrGlintSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrGlintReader != null) {
                            zephyrGlintReader.close();
                        }
                        if (zephyrGlintStreamReader != null) {
                            zephyrGlintStreamReader.close();
                        }
                        if (zephyrGlintStream != null) {
                            zephyrGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_ZephyrGlintSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
