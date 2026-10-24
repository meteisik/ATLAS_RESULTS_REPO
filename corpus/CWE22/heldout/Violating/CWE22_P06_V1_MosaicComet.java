import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_MosaicComet {

    public void openMosaicComet() {
        String data;
        data = System.getenv("MOSAIC_COMET_PATH");
        (new CWE22_P06_V1_MosaicCometSink()).readMosaicComet(data);
    }
}

class CWE22_P06_V1_MosaicCometSink {
    public void readMosaicComet(String data) {
        String mosaicCometRoot = "/home/user/uploads/";
        if (data != null) {
            File mosaicCometFile = new File(mosaicCometRoot + data);
            FileInputStream mosaicCometStream = null;
            InputStreamReader mosaicCometStreamReader = null;
            BufferedReader mosaicCometReader = null;
            if (mosaicCometFile.exists() && mosaicCometFile.isFile()) {
                try {
                    mosaicCometStream = new FileInputStream(mosaicCometFile);
                    mosaicCometStreamReader = new InputStreamReader(mosaicCometStream, "UTF-8");
                    mosaicCometReader = new BufferedReader(mosaicCometStreamReader);
                    System.out.println(mosaicCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V1_MosaicCometSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (mosaicCometReader != null) {
                            mosaicCometReader.close();
                        }
                        if (mosaicCometStreamReader != null) {
                            mosaicCometStreamReader.close();
                        }
                        if (mosaicCometStream != null) {
                            mosaicCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V1_MosaicCometSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
