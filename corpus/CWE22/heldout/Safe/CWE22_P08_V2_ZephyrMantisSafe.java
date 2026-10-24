import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_ZephyrMantisSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openZephyrMantis() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_ZephyrMantisSafeSink()).readZephyrMantis(dataArray);
    }
}

class CWE22_P08_V2_ZephyrMantisSafeSink {
    public void readZephyrMantis(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V2_ZephyrMantisSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V2_ZephyrMantisSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
