import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V1_ArcticBeacon {

    public void openArcticBeacon() {
        String data;
        data = System.getenv("ARCTIC_BEACON_PATH");
        String arcticBeaconRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticBeaconFile = new File(arcticBeaconRoot + data);
            FileInputStream arcticBeaconStream = null;
            InputStreamReader arcticBeaconStreamReader = null;
            BufferedReader arcticBeaconReader = null;
            if (arcticBeaconFile.exists() && arcticBeaconFile.isFile()) {
                try {
                    arcticBeaconStream = new FileInputStream(arcticBeaconFile);
                    arcticBeaconStreamReader = new InputStreamReader(arcticBeaconStream, "UTF-8");
                    arcticBeaconReader = new BufferedReader(arcticBeaconStreamReader);
                    System.out.println(arcticBeaconReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V1_ArcticBeacon").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticBeaconReader != null) {
                            arcticBeaconReader.close();
                        }
                        if (arcticBeaconStreamReader != null) {
                            arcticBeaconStreamReader.close();
                        }
                        if (arcticBeaconStream != null) {
                            arcticBeaconStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V1_ArcticBeacon").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
