import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V1_MosaicLotusSafe {

    public void openMosaicLotus() {
        String data;
        data = (new CWE22_P07_V1_MosaicLotusSafeSource()).locateMosaicLotus();
        String mosaicLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File mosaicLotusFile = new File(mosaicLotusRoot + data);
            FileInputStream mosaicLotusStream = null;
            InputStreamReader mosaicLotusStreamReader = null;
            BufferedReader mosaicLotusReader = null;
            if (mosaicLotusFile.exists() && mosaicLotusFile.isFile()) {
                try {
                    mosaicLotusStream = new FileInputStream(mosaicLotusFile);
                    mosaicLotusStreamReader = new InputStreamReader(mosaicLotusStream, "UTF-8");
                    mosaicLotusReader = new BufferedReader(mosaicLotusStreamReader);
                    System.out.println(mosaicLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V1_MosaicLotusSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (mosaicLotusReader != null) {
                            mosaicLotusReader.close();
                        }
                        if (mosaicLotusStreamReader != null) {
                            mosaicLotusStreamReader.close();
                        }
                        if (mosaicLotusStream != null) {
                            mosaicLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V1_MosaicLotusSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V1_MosaicLotusSafeSource {
    public String locateMosaicLotus() {
        String data;
        data = "foo";
        return data;
    }
}
