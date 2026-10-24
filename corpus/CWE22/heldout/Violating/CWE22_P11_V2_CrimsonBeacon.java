import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_CrimsonBeacon {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openCrimsonBeacon() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_BEACON_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_CrimsonBeaconSink()).readCrimsonBeacon(dataHashMap);
    }
}

class CWE22_P11_V2_CrimsonBeaconSink {
    public void readCrimsonBeacon(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String crimsonBeaconRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonBeaconFile = new File(crimsonBeaconRoot + data);
            FileInputStream crimsonBeaconStream = null;
            InputStreamReader crimsonBeaconStreamReader = null;
            BufferedReader crimsonBeaconReader = null;
            if (crimsonBeaconFile.exists() && crimsonBeaconFile.isFile()) {
                try {
                    crimsonBeaconStream = new FileInputStream(crimsonBeaconFile);
                    crimsonBeaconStreamReader = new InputStreamReader(crimsonBeaconStream, "UTF-8");
                    crimsonBeaconReader = new BufferedReader(crimsonBeaconStreamReader);
                    System.out.println(crimsonBeaconReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_CrimsonBeaconSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonBeaconReader != null) {
                            crimsonBeaconReader.close();
                        }
                        if (crimsonBeaconStreamReader != null) {
                            crimsonBeaconStreamReader.close();
                        }
                        if (crimsonBeaconStream != null) {
                            crimsonBeaconStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_CrimsonBeaconSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
