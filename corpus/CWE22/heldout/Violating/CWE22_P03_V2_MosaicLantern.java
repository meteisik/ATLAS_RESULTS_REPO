import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V2_MosaicLantern {
    private static boolean privateTrue = true;

    private void readMosaicLantern(String data) {
        String mosaicLanternRoot = "/home/user/uploads/";
        if (data != null) {
            File mosaicLanternFile = new File(mosaicLanternRoot + data);
            FileInputStream mosaicLanternStream = null;
            InputStreamReader mosaicLanternStreamReader = null;
            BufferedReader mosaicLanternReader = null;
            if (mosaicLanternFile.exists() && mosaicLanternFile.isFile()) {
                try {
                    mosaicLanternStream = new FileInputStream(mosaicLanternFile);
                    mosaicLanternStreamReader = new InputStreamReader(mosaicLanternStream, "UTF-8");
                    mosaicLanternReader = new BufferedReader(mosaicLanternStreamReader);
                    System.out.println(mosaicLanternReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V2_MosaicLantern").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (mosaicLanternReader != null) {
                            mosaicLanternReader.close();
                        }
                        if (mosaicLanternStreamReader != null) {
                            mosaicLanternStreamReader.close();
                        }
                        if (mosaicLanternStream != null) {
                            mosaicLanternStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V2_MosaicLantern").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openMosaicLantern() {
        String data;
        if (privateTrue) {
            data = System.getenv("MOSAIC_LANTERN_PATH");
        } else {
            data = null;
        }
        readMosaicLantern(data);
    }
}
