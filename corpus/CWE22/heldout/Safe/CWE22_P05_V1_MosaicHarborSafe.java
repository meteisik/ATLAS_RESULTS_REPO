import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V1_MosaicHarborSafe {
    private String mosaicHarborData;

    private void readMosaicHarbor() {
        String data = mosaicHarborData;
        String mosaicHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File mosaicHarborFile = new File(mosaicHarborRoot + data);
            FileInputStream mosaicHarborStream = null;
            InputStreamReader mosaicHarborStreamReader = null;
            BufferedReader mosaicHarborReader = null;
            if (mosaicHarborFile.exists() && mosaicHarborFile.isFile()) {
                try {
                    mosaicHarborStream = new FileInputStream(mosaicHarborFile);
                    mosaicHarborStreamReader = new InputStreamReader(mosaicHarborStream, "UTF-8");
                    mosaicHarborReader = new BufferedReader(mosaicHarborStreamReader);
                    System.out.println(mosaicHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V1_MosaicHarborSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (mosaicHarborReader != null) {
                            mosaicHarborReader.close();
                        }
                        if (mosaicHarborStreamReader != null) {
                            mosaicHarborStreamReader.close();
                        }
                        if (mosaicHarborStream != null) {
                            mosaicHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V1_MosaicHarborSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openMosaicHarbor() {
        String data;
        data = "foo";
        mosaicHarborData = data;
        readMosaicHarbor();
    }
}
