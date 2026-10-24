import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ArcticBeaconSafe {

    public void openArcticBeacon() {
        String data;
        data = "foo";
        CWE22_P12_V1_ArcticBeaconSafeBase baseObject = new CWE22_P12_V1_ArcticBeaconSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ArcticBeaconSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ArcticBeaconSafeSink extends CWE22_P12_V1_ArcticBeaconSafeBase {
    public void action(String data) {
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
                    Logger.getLogger("CWE22_P12_V1_ArcticBeaconSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V1_ArcticBeaconSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
