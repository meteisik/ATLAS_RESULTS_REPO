import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_ZephyrSundial {
    public static String data;

    public void openZephyrSundial() {
        switch (7) {
        case 7:
            data = System.getenv("ZEPHYR_SUNDIAL_PATH");
            break;
        default:
            data = null;
            break;
        }
        (new CWE22_P10_V2_ZephyrSundialSink()).readZephyrSundial();
    }
}

class CWE22_P10_V2_ZephyrSundialSink {
    public void readZephyrSundial() {
        String data = CWE22_P10_V2_ZephyrSundial.data;
        String zephyrSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrSundialFile = new File(zephyrSundialRoot + data);
            FileInputStream zephyrSundialStream = null;
            InputStreamReader zephyrSundialStreamReader = null;
            BufferedReader zephyrSundialReader = null;
            if (zephyrSundialFile.exists() && zephyrSundialFile.isFile()) {
                try {
                    zephyrSundialStream = new FileInputStream(zephyrSundialFile);
                    zephyrSundialStreamReader = new InputStreamReader(zephyrSundialStream, "UTF-8");
                    zephyrSundialReader = new BufferedReader(zephyrSundialStreamReader);
                    System.out.println(zephyrSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_ZephyrSundialSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrSundialReader != null) {
                            zephyrSundialReader.close();
                        }
                        if (zephyrSundialStreamReader != null) {
                            zephyrSundialStreamReader.close();
                        }
                        if (zephyrSundialStream != null) {
                            zephyrSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_ZephyrSundialSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
