import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_ZephyrCascade {
    public static String data;
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openZephyrCascade() {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_CASCADE_PATH");
        } else {
            data = null;
        }
        (new CWE22_P10_V2_ZephyrCascadeSink()).readZephyrCascade();
    }
}

class CWE22_P10_V2_ZephyrCascadeSink {
    public void readZephyrCascade() {
        String data = CWE22_P10_V2_ZephyrCascade.data;
        String zephyrCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrCascadeFile = new File(zephyrCascadeRoot + data);
            FileInputStream zephyrCascadeStream = null;
            InputStreamReader zephyrCascadeStreamReader = null;
            BufferedReader zephyrCascadeReader = null;
            if (zephyrCascadeFile.exists() && zephyrCascadeFile.isFile()) {
                try {
                    zephyrCascadeStream = new FileInputStream(zephyrCascadeFile);
                    zephyrCascadeStreamReader = new InputStreamReader(zephyrCascadeStream, "UTF-8");
                    zephyrCascadeReader = new BufferedReader(zephyrCascadeStreamReader);
                    System.out.println(zephyrCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_ZephyrCascadeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrCascadeReader != null) {
                            zephyrCascadeReader.close();
                        }
                        if (zephyrCascadeStreamReader != null) {
                            zephyrCascadeStreamReader.close();
                        }
                        if (zephyrCascadeStream != null) {
                            zephyrCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_ZephyrCascadeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
