import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V2_MosaicBeacon {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openMosaicBeacon() {
        String dataCopy;
        {
            String data;
            if (IO.staticFive == 5) {
                data = System.getenv("MOSAIC_BEACON_PATH");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
                        Logger.getLogger("CWE22_P02_V2_MosaicBeacon").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                            Logger.getLogger("CWE22_P02_V2_MosaicBeacon").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}
