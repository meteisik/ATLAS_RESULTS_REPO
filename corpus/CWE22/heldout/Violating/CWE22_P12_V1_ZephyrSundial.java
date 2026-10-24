import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ZephyrSundial {

    public void openZephyrSundial() {
        String data;
        data = System.getenv("ZEPHYR_SUNDIAL_PATH");
        CWE22_P12_V1_ZephyrSundialBase baseObject = new CWE22_P12_V1_ZephyrSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ZephyrSundialBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ZephyrSundialSink extends CWE22_P12_V1_ZephyrSundialBase {
    public void action(String data) {
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
                    Logger.getLogger("CWE22_P12_V1_ZephyrSundialSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V1_ZephyrSundialSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
