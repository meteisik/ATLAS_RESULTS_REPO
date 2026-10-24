import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_CrimsonBeacon {

    public void openCrimsonBeacon() {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_BEACON_PATH");
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
                        Logger.getLogger("CWE22_P02_V1_CrimsonBeacon").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                            Logger.getLogger("CWE22_P02_V1_CrimsonBeacon").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}
