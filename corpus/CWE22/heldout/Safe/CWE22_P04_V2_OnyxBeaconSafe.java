import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V2_OnyxBeaconSafe {

    private String locateOnyxBeacon() {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        return data;
    }

    public void openOnyxBeacon() {
        String data = locateOnyxBeacon();
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
                    Logger.getLogger("CWE22_P04_V2_OnyxBeaconSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P04_V2_OnyxBeaconSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
