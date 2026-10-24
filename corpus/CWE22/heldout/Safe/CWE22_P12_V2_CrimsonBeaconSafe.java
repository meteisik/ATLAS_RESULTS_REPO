import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_CrimsonBeaconSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void openCrimsonBeacon() {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        CWE22_P12_V2_CrimsonBeaconSafeBase baseObject = new CWE22_P12_V2_CrimsonBeaconSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_CrimsonBeaconSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_CrimsonBeaconSafeSink extends CWE22_P12_V2_CrimsonBeaconSafeBase {
    public void action(String data) {
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
                    Logger.getLogger("CWE22_P12_V2_CrimsonBeaconSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V2_CrimsonBeaconSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
