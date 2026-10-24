import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V1_ObsidianBeaconSafe {

    public void openObsidianBeacon() {
        String data;
        data = (new CWE22_P07_V1_ObsidianBeaconSafeSource()).locateObsidianBeacon();
        String obsidianBeaconRoot = "/home/user/uploads/";
        if (data != null) {
            File obsidianBeaconFile = new File(obsidianBeaconRoot + data);
            FileInputStream obsidianBeaconStream = null;
            InputStreamReader obsidianBeaconStreamReader = null;
            BufferedReader obsidianBeaconReader = null;
            if (obsidianBeaconFile.exists() && obsidianBeaconFile.isFile()) {
                try {
                    obsidianBeaconStream = new FileInputStream(obsidianBeaconFile);
                    obsidianBeaconStreamReader = new InputStreamReader(obsidianBeaconStream, "UTF-8");
                    obsidianBeaconReader = new BufferedReader(obsidianBeaconStreamReader);
                    System.out.println(obsidianBeaconReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V1_ObsidianBeaconSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (obsidianBeaconReader != null) {
                            obsidianBeaconReader.close();
                        }
                        if (obsidianBeaconStreamReader != null) {
                            obsidianBeaconStreamReader.close();
                        }
                        if (obsidianBeaconStream != null) {
                            obsidianBeaconStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V1_ObsidianBeaconSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V1_ObsidianBeaconSafeSource {
    public String locateObsidianBeacon() {
        String data;
        data = "foo";
        return data;
    }
}
