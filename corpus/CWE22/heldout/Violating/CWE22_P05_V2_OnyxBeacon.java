import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V2_OnyxBeacon {
    private String onyxBeaconData;

    private void readOnyxBeacon() {
        String data = onyxBeaconData;
        String onyxBeaconRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxBeaconFile = new File(onyxBeaconRoot + data);
            FileInputStream onyxBeaconStream = null;
            InputStreamReader onyxBeaconStreamReader = null;
            BufferedReader onyxBeaconReader = null;
            if (onyxBeaconFile.exists() && onyxBeaconFile.isFile()) {
                try {
                    onyxBeaconStream = new FileInputStream(onyxBeaconFile);
                    onyxBeaconStreamReader = new InputStreamReader(onyxBeaconStream, "UTF-8");
                    onyxBeaconReader = new BufferedReader(onyxBeaconStreamReader);
                    System.out.println(onyxBeaconReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V2_OnyxBeacon").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxBeaconReader != null) {
                            onyxBeaconReader.close();
                        }
                        if (onyxBeaconStreamReader != null) {
                            onyxBeaconStreamReader.close();
                        }
                        if (onyxBeaconStream != null) {
                            onyxBeaconStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V2_OnyxBeacon").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openOnyxBeacon() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ONYX_BEACON_PATH");
        }
        onyxBeaconData = data;
        readOnyxBeacon();
    }
}
