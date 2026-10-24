import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_ZephyrMantis {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String containerOne;
    }

    public void openZephyrMantis() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ZEPHYR_MANTIS_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_ZephyrMantisSink()).readZephyrMantis(dataContainer);
    }
}

class CWE22_P09_V2_ZephyrMantisSink {
    public void readZephyrMantis(CWE22_P09_V2_ZephyrMantis.Container dataContainer) {
        String data = dataContainer.containerOne;
        String zephyrMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrMantisFile = new File(zephyrMantisRoot + data);
            FileInputStream zephyrMantisStream = null;
            InputStreamReader zephyrMantisStreamReader = null;
            BufferedReader zephyrMantisReader = null;
            if (zephyrMantisFile.exists() && zephyrMantisFile.isFile()) {
                try {
                    zephyrMantisStream = new FileInputStream(zephyrMantisFile);
                    zephyrMantisStreamReader = new InputStreamReader(zephyrMantisStream, "UTF-8");
                    zephyrMantisReader = new BufferedReader(zephyrMantisStreamReader);
                    System.out.println(zephyrMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_ZephyrMantisSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrMantisReader != null) {
                            zephyrMantisReader.close();
                        }
                        if (zephyrMantisStreamReader != null) {
                            zephyrMantisStreamReader.close();
                        }
                        if (zephyrMantisStream != null) {
                            zephyrMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_ZephyrMantisSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
