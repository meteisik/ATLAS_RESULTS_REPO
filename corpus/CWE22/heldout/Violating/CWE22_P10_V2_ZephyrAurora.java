import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_ZephyrAurora {
    public static String data;
    private static boolean privateTrue = true;

    public void openZephyrAurora() {
        if (privateTrue) {
            data = System.getenv("ZEPHYR_AURORA_PATH");
        } else {
            data = null;
        }
        (new CWE22_P10_V2_ZephyrAuroraSink()).readZephyrAurora();
    }
}

class CWE22_P10_V2_ZephyrAuroraSink {
    public void readZephyrAurora() {
        String data = CWE22_P10_V2_ZephyrAurora.data;
        String zephyrAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrAuroraFile = new File(zephyrAuroraRoot + data);
            FileInputStream zephyrAuroraStream = null;
            InputStreamReader zephyrAuroraStreamReader = null;
            BufferedReader zephyrAuroraReader = null;
            if (zephyrAuroraFile.exists() && zephyrAuroraFile.isFile()) {
                try {
                    zephyrAuroraStream = new FileInputStream(zephyrAuroraFile);
                    zephyrAuroraStreamReader = new InputStreamReader(zephyrAuroraStream, "UTF-8");
                    zephyrAuroraReader = new BufferedReader(zephyrAuroraStreamReader);
                    System.out.println(zephyrAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_ZephyrAuroraSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrAuroraReader != null) {
                            zephyrAuroraReader.close();
                        }
                        if (zephyrAuroraStreamReader != null) {
                            zephyrAuroraStreamReader.close();
                        }
                        if (zephyrAuroraStream != null) {
                            zephyrAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_ZephyrAuroraSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
