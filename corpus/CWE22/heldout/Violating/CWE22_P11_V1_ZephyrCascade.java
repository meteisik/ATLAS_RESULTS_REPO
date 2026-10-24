import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_ZephyrCascade {

    public void openZephyrCascade() {
        String data;
        data = System.getenv("ZEPHYR_CASCADE_PATH");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_ZephyrCascadeSink()).readZephyrCascade(dataHashMap);
    }
}

class CWE22_P11_V1_ZephyrCascadeSink {
    public void readZephyrCascade(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
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
                    Logger.getLogger("CWE22_P11_V1_ZephyrCascadeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P11_V1_ZephyrCascadeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
