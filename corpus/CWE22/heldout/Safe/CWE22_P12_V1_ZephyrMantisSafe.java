import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ZephyrMantisSafe {

    public void openZephyrMantis() {
        String data;
        data = "foo";
        CWE22_P12_V1_ZephyrMantisSafeBase baseObject = new CWE22_P12_V1_ZephyrMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ZephyrMantisSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ZephyrMantisSafeSink extends CWE22_P12_V1_ZephyrMantisSafeBase {
    public void action(String data) {
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
                    Logger.getLogger("CWE22_P12_V1_ZephyrMantisSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V1_ZephyrMantisSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
