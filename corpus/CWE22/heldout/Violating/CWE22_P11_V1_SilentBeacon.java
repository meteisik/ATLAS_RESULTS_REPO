import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_SilentBeacon {

    public void openSilentBeacon() {
        String data;
        data = System.getenv("SILENT_BEACON_PATH");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_SilentBeaconSink()).readSilentBeacon(dataHashMap);
    }
}

class CWE22_P11_V1_SilentBeaconSink {
    public void readSilentBeacon(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String silentBeaconRoot = "/home/user/uploads/";
        if (data != null) {
            File silentBeaconFile = new File(silentBeaconRoot + data);
            FileInputStream silentBeaconStream = null;
            InputStreamReader silentBeaconStreamReader = null;
            BufferedReader silentBeaconReader = null;
            if (silentBeaconFile.exists() && silentBeaconFile.isFile()) {
                try {
                    silentBeaconStream = new FileInputStream(silentBeaconFile);
                    silentBeaconStreamReader = new InputStreamReader(silentBeaconStream, "UTF-8");
                    silentBeaconReader = new BufferedReader(silentBeaconStreamReader);
                    System.out.println(silentBeaconReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_SilentBeaconSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentBeaconReader != null) {
                            silentBeaconReader.close();
                        }
                        if (silentBeaconStreamReader != null) {
                            silentBeaconStreamReader.close();
                        }
                        if (silentBeaconStream != null) {
                            silentBeaconStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_SilentBeaconSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
