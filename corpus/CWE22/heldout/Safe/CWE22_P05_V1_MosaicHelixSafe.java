import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V1_MosaicHelixSafe {
    private String mosaicHelixData;

    private void readMosaicHelix() {
        String data = mosaicHelixData;
        String mosaicHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File mosaicHelixFile = new File(mosaicHelixRoot + data);
            FileInputStream mosaicHelixStream = null;
            InputStreamReader mosaicHelixStreamReader = null;
            BufferedReader mosaicHelixReader = null;
            if (mosaicHelixFile.exists() && mosaicHelixFile.isFile()) {
                try {
                    mosaicHelixStream = new FileInputStream(mosaicHelixFile);
                    mosaicHelixStreamReader = new InputStreamReader(mosaicHelixStream, "UTF-8");
                    mosaicHelixReader = new BufferedReader(mosaicHelixStreamReader);
                    System.out.println(mosaicHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V1_MosaicHelixSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (mosaicHelixReader != null) {
                            mosaicHelixReader.close();
                        }
                        if (mosaicHelixStreamReader != null) {
                            mosaicHelixStreamReader.close();
                        }
                        if (mosaicHelixStream != null) {
                            mosaicHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V1_MosaicHelixSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openMosaicHelix() {
        String data;
        data = "foo";
        mosaicHelixData = data;
        readMosaicHelix();
    }
}
