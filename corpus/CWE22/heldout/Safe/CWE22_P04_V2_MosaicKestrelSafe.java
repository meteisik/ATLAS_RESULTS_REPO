import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V2_MosaicKestrelSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String locateMosaicKestrel() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void openMosaicKestrel() {
        String data = locateMosaicKestrel();
        String mosaicKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File mosaicKestrelFile = new File(mosaicKestrelRoot + data);
            FileInputStream mosaicKestrelStream = null;
            InputStreamReader mosaicKestrelStreamReader = null;
            BufferedReader mosaicKestrelReader = null;
            if (mosaicKestrelFile.exists() && mosaicKestrelFile.isFile()) {
                try {
                    mosaicKestrelStream = new FileInputStream(mosaicKestrelFile);
                    mosaicKestrelStreamReader = new InputStreamReader(mosaicKestrelStream, "UTF-8");
                    mosaicKestrelReader = new BufferedReader(mosaicKestrelStreamReader);
                    System.out.println(mosaicKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V2_MosaicKestrelSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (mosaicKestrelReader != null) {
                            mosaicKestrelReader.close();
                        }
                        if (mosaicKestrelStreamReader != null) {
                            mosaicKestrelStreamReader.close();
                        }
                        if (mosaicKestrelStream != null) {
                            mosaicKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V2_MosaicKestrelSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
