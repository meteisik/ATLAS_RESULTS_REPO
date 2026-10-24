import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_ZephyrGlintSafe {

    public void openZephyrGlint() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_ZephyrGlintSafeSink()).readZephyrGlint(dataHashMap);
    }
}

class CWE22_P11_V1_ZephyrGlintSafeSink {
    public void readZephyrGlint(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String zephyrGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrGlintFile = new File(zephyrGlintRoot + data);
            FileInputStream zephyrGlintStream = null;
            InputStreamReader zephyrGlintStreamReader = null;
            BufferedReader zephyrGlintReader = null;
            if (zephyrGlintFile.exists() && zephyrGlintFile.isFile()) {
                try {
                    zephyrGlintStream = new FileInputStream(zephyrGlintFile);
                    zephyrGlintStreamReader = new InputStreamReader(zephyrGlintStream, "UTF-8");
                    zephyrGlintReader = new BufferedReader(zephyrGlintStreamReader);
                    System.out.println(zephyrGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_ZephyrGlintSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrGlintReader != null) {
                            zephyrGlintReader.close();
                        }
                        if (zephyrGlintStreamReader != null) {
                            zephyrGlintStreamReader.close();
                        }
                        if (zephyrGlintStream != null) {
                            zephyrGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_ZephyrGlintSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
