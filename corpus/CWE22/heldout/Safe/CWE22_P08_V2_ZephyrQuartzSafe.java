import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_ZephyrQuartzSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void openZephyrQuartz() {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_ZephyrQuartzSafeSink()).readZephyrQuartz(dataArray);
    }
}

class CWE22_P08_V2_ZephyrQuartzSafeSink {
    public void readZephyrQuartz(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V2_ZephyrQuartzSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V2_ZephyrQuartzSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
