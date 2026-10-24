import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_ZephyrSignal {
    public static String data;
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openZephyrSignal() {
        if (IO.staticFive == 5) {
            data = System.getenv("ZEPHYR_SIGNAL_PATH");
        } else {
            data = null;
        }
        (new CWE22_P10_V2_ZephyrSignalSink()).readZephyrSignal();
    }
}

class CWE22_P10_V2_ZephyrSignalSink {
    public void readZephyrSignal() {
        String data = CWE22_P10_V2_ZephyrSignal.data;
        String zephyrSignalRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrSignalFile = new File(zephyrSignalRoot + data);
            FileInputStream zephyrSignalStream = null;
            InputStreamReader zephyrSignalStreamReader = null;
            BufferedReader zephyrSignalReader = null;
            if (zephyrSignalFile.exists() && zephyrSignalFile.isFile()) {
                try {
                    zephyrSignalStream = new FileInputStream(zephyrSignalFile);
                    zephyrSignalStreamReader = new InputStreamReader(zephyrSignalStream, "UTF-8");
                    zephyrSignalReader = new BufferedReader(zephyrSignalStreamReader);
                    System.out.println(zephyrSignalReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_ZephyrSignalSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrSignalReader != null) {
                            zephyrSignalReader.close();
                        }
                        if (zephyrSignalStreamReader != null) {
                            zephyrSignalStreamReader.close();
                        }
                        if (zephyrSignalStream != null) {
                            zephyrSignalStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_ZephyrSignalSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
