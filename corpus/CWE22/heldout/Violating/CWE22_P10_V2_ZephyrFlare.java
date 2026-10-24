import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_ZephyrFlare {
    public static String data;
    private static boolean privateReturnsTrue() { return true; }

    public void openZephyrFlare() {
        if (privateReturnsTrue()) {
            data = System.getenv("ZEPHYR_FLARE_PATH");
        } else {
            data = null;
        }
        (new CWE22_P10_V2_ZephyrFlareSink()).readZephyrFlare();
    }
}

class CWE22_P10_V2_ZephyrFlareSink {
    public void readZephyrFlare() {
        String data = CWE22_P10_V2_ZephyrFlare.data;
        String zephyrFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrFlareFile = new File(zephyrFlareRoot + data);
            FileInputStream zephyrFlareStream = null;
            InputStreamReader zephyrFlareStreamReader = null;
            BufferedReader zephyrFlareReader = null;
            if (zephyrFlareFile.exists() && zephyrFlareFile.isFile()) {
                try {
                    zephyrFlareStream = new FileInputStream(zephyrFlareFile);
                    zephyrFlareStreamReader = new InputStreamReader(zephyrFlareStream, "UTF-8");
                    zephyrFlareReader = new BufferedReader(zephyrFlareStreamReader);
                    System.out.println(zephyrFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_ZephyrFlareSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrFlareReader != null) {
                            zephyrFlareReader.close();
                        }
                        if (zephyrFlareStreamReader != null) {
                            zephyrFlareStreamReader.close();
                        }
                        if (zephyrFlareStream != null) {
                            zephyrFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_ZephyrFlareSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
