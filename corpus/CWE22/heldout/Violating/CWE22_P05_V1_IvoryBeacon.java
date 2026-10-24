import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V1_IvoryBeacon {
    private String ivoryBeaconData;

    private void readIvoryBeacon() {
        String data = ivoryBeaconData;
        String ivoryBeaconRoot = "/home/user/uploads/";
        if (data != null) {
            File ivoryBeaconFile = new File(ivoryBeaconRoot + data);
            FileInputStream ivoryBeaconStream = null;
            InputStreamReader ivoryBeaconStreamReader = null;
            BufferedReader ivoryBeaconReader = null;
            if (ivoryBeaconFile.exists() && ivoryBeaconFile.isFile()) {
                try {
                    ivoryBeaconStream = new FileInputStream(ivoryBeaconFile);
                    ivoryBeaconStreamReader = new InputStreamReader(ivoryBeaconStream, "UTF-8");
                    ivoryBeaconReader = new BufferedReader(ivoryBeaconStreamReader);
                    System.out.println(ivoryBeaconReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V1_IvoryBeacon").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (ivoryBeaconReader != null) {
                            ivoryBeaconReader.close();
                        }
                        if (ivoryBeaconStreamReader != null) {
                            ivoryBeaconStreamReader.close();
                        }
                        if (ivoryBeaconStream != null) {
                            ivoryBeaconStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V1_IvoryBeacon").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openIvoryBeacon() {
        String data;
        data = System.getenv("IVORY_BEACON_PATH");
        ivoryBeaconData = data;
        readIvoryBeacon();
    }
}
