import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_SilentBeaconSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openSilentBeacon() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_SilentBeaconSafeSink()).readSilentBeacon(dataArray);
    }
}

class CWE22_P08_V2_SilentBeaconSafeSink {
    public void readSilentBeacon(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V2_SilentBeaconSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V2_SilentBeaconSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
