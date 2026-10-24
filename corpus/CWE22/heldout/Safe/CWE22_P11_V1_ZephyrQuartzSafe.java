import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_ZephyrQuartzSafe {

    public void openZephyrQuartz() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_ZephyrQuartzSafeSink()).readZephyrQuartz(dataHashMap);
    }
}

class CWE22_P11_V1_ZephyrQuartzSafeSink {
    public void readZephyrQuartz(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
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
                    Logger.getLogger("CWE22_P11_V1_ZephyrQuartzSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P11_V1_ZephyrQuartzSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
