import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_ArcticBeacon {
    private static int privateFive = 5;

    static class Container {
        public String containerOne;
    }

    public void openArcticBeacon() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ARCTIC_BEACON_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_ArcticBeaconSink()).readArcticBeacon(dataContainer);
    }
}

class CWE22_P09_V2_ArcticBeaconSink {
    public void readArcticBeacon(CWE22_P09_V2_ArcticBeacon.Container dataContainer) {
        String data = dataContainer.containerOne;
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
                    Logger.getLogger("CWE22_P09_V2_ArcticBeaconSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P09_V2_ArcticBeaconSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
