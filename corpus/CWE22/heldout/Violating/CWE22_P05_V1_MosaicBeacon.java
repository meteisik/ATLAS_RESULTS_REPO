import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V1_MosaicBeacon {
    private String mosaicBeaconData;

    private void readMosaicBeacon() {
        String data = mosaicBeaconData;
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
                    Logger.getLogger("CWE22_P05_V1_MosaicBeacon").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P05_V1_MosaicBeacon").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openMosaicBeacon() {
        String data;
        data = System.getenv("MOSAIC_BEACON_PATH");
        mosaicBeaconData = data;
        readMosaicBeacon();
    }
}
