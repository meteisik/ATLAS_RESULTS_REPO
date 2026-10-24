import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V1_SilentBeacon {
    public static String data;

    public void openSilentBeacon() {
        data = System.getenv("SILENT_BEACON_PATH");
        (new CWE22_P10_V1_SilentBeaconSink()).readSilentBeacon();
    }
}

class CWE22_P10_V1_SilentBeaconSink {
    public void readSilentBeacon() {
        String data = CWE22_P10_V1_SilentBeacon.data;
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
                    Logger.getLogger("CWE22_P10_V1_SilentBeaconSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P10_V1_SilentBeaconSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
