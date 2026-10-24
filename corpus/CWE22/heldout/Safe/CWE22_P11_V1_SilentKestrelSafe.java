import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_SilentKestrelSafe {

    public void openSilentKestrel() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_SilentKestrelSafeSink()).readSilentKestrel(dataHashMap);
    }
}

class CWE22_P11_V1_SilentKestrelSafeSink {
    public void readSilentKestrel(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String silentKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File silentKestrelFile = new File(silentKestrelRoot + data);
            FileInputStream silentKestrelStream = null;
            InputStreamReader silentKestrelStreamReader = null;
            BufferedReader silentKestrelReader = null;
            if (silentKestrelFile.exists() && silentKestrelFile.isFile()) {
                try {
                    silentKestrelStream = new FileInputStream(silentKestrelFile);
                    silentKestrelStreamReader = new InputStreamReader(silentKestrelStream, "UTF-8");
                    silentKestrelReader = new BufferedReader(silentKestrelStreamReader);
                    System.out.println(silentKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_SilentKestrelSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentKestrelReader != null) {
                            silentKestrelReader.close();
                        }
                        if (silentKestrelStreamReader != null) {
                            silentKestrelStreamReader.close();
                        }
                        if (silentKestrelStream != null) {
                            silentKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_SilentKestrelSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
