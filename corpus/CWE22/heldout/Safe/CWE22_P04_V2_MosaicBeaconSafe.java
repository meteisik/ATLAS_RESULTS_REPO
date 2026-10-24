import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V2_MosaicBeaconSafe {

    private String locateMosaicBeacon() {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void openMosaicBeacon() {
        String data = locateMosaicBeacon();
        String mosaicBeaconRoot = "/home/user/uploads/";
        if (data != null) {
            File mosaicBeaconFile = new File(mosaicBeaconRoot + data);
            FileInputStream mosaicBeaconStream = null;
            InputStreamReader mosaicBeaconStreamReader = null;
            BufferedReader mosaicBeaconReader = null;
            if (mosaicBeaconFile.exists() && mosaicBeaconFile.isFile()) {
                try {
                    mosaicBeaconStream = new FileInputStream(mosaicBeaconFile);
                    mosaicBeaconStreamReader = new InputStreamReader(mosaicBeaconStream, "UTF-8");
                    mosaicBeaconReader = new BufferedReader(mosaicBeaconStreamReader);
                    System.out.println(mosaicBeaconReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V2_MosaicBeaconSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (mosaicBeaconReader != null) {
                            mosaicBeaconReader.close();
                        }
                        if (mosaicBeaconStreamReader != null) {
                            mosaicBeaconStreamReader.close();
                        }
                        if (mosaicBeaconStream != null) {
                            mosaicBeaconStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V2_MosaicBeaconSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
