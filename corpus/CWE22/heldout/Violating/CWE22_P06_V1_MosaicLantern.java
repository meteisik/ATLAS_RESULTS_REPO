import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_MosaicLantern {

    public void openMosaicLantern() {
        String data;
        data = System.getenv("MOSAIC_LANTERN_PATH");
        (new CWE22_P06_V1_MosaicLanternSink()).readMosaicLantern(data);
    }
}

class CWE22_P06_V1_MosaicLanternSink {
    public void readMosaicLantern(String data) {
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
                    Logger.getLogger("CWE22_P06_V1_MosaicLanternSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P06_V1_MosaicLanternSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
