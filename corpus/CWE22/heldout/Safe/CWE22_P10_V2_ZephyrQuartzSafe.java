import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_ZephyrQuartzSafe {
    public static String data;
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openZephyrQuartz() {
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE22_P10_V2_ZephyrQuartzSafeSink()).readZephyrQuartz();
    }
}

class CWE22_P10_V2_ZephyrQuartzSafeSink {
    public void readZephyrQuartz() {
        String data = CWE22_P10_V2_ZephyrQuartzSafe.data;
        String zephyrQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrQuartzFile = new File(zephyrQuartzRoot + data);
            FileInputStream zephyrQuartzStream = null;
            InputStreamReader zephyrQuartzStreamReader = null;
            BufferedReader zephyrQuartzReader = null;
            if (zephyrQuartzFile.exists() && zephyrQuartzFile.isFile()) {
                try {
                    zephyrQuartzStream = new FileInputStream(zephyrQuartzFile);
                    zephyrQuartzStreamReader = new InputStreamReader(zephyrQuartzStream, "UTF-8");
                    zephyrQuartzReader = new BufferedReader(zephyrQuartzStreamReader);
                    System.out.println(zephyrQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_ZephyrQuartzSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrQuartzReader != null) {
                            zephyrQuartzReader.close();
                        }
                        if (zephyrQuartzStreamReader != null) {
                            zephyrQuartzStreamReader.close();
                        }
                        if (zephyrQuartzStream != null) {
                            zephyrQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_ZephyrQuartzSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
