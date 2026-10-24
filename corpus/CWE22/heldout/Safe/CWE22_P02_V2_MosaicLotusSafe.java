import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V2_MosaicLotusSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void openMosaicLotus() {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_TRUE) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
                        Logger.getLogger("CWE22_P02_V2_MosaicLotusSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                            Logger.getLogger("CWE22_P02_V2_MosaicLotusSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}
