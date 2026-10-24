import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_SilentLanternSafe {

    public void openSilentLantern() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_SilentLanternSafeSink()).readSilentLantern(dataHashMap);
    }
}

class CWE22_P11_V1_SilentLanternSafeSink {
    public void readSilentLantern(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String silentLanternRoot = "/home/user/uploads/";
        if (data != null) {
            File silentLanternFile = new File(silentLanternRoot + data);
            FileInputStream silentLanternStream = null;
            InputStreamReader silentLanternStreamReader = null;
            BufferedReader silentLanternReader = null;
            if (silentLanternFile.exists() && silentLanternFile.isFile()) {
                try {
                    silentLanternStream = new FileInputStream(silentLanternFile);
                    silentLanternStreamReader = new InputStreamReader(silentLanternStream, "UTF-8");
                    silentLanternReader = new BufferedReader(silentLanternStreamReader);
                    System.out.println(silentLanternReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_SilentLanternSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentLanternReader != null) {
                            silentLanternReader.close();
                        }
                        if (silentLanternStreamReader != null) {
                            silentLanternStreamReader.close();
                        }
                        if (silentLanternStream != null) {
                            silentLanternStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_SilentLanternSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
