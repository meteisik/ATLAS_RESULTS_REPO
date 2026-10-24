import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_MosaicNebula {

    public void openMosaicNebula() {
        String data;
        data = System.getenv("MOSAIC_NEBULA_PATH");
        (new CWE22_P06_V1_MosaicNebulaSink()).readMosaicNebula(data);
    }
}

class CWE22_P06_V1_MosaicNebulaSink {
    public void readMosaicNebula(String data) {
        String mosaicNebulaRoot = "/home/user/uploads/";
        if (data != null) {
            File mosaicNebulaFile = new File(mosaicNebulaRoot + data);
            FileInputStream mosaicNebulaStream = null;
            InputStreamReader mosaicNebulaStreamReader = null;
            BufferedReader mosaicNebulaReader = null;
            if (mosaicNebulaFile.exists() && mosaicNebulaFile.isFile()) {
                try {
                    mosaicNebulaStream = new FileInputStream(mosaicNebulaFile);
                    mosaicNebulaStreamReader = new InputStreamReader(mosaicNebulaStream, "UTF-8");
                    mosaicNebulaReader = new BufferedReader(mosaicNebulaStreamReader);
                    System.out.println(mosaicNebulaReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V1_MosaicNebulaSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (mosaicNebulaReader != null) {
                            mosaicNebulaReader.close();
                        }
                        if (mosaicNebulaStreamReader != null) {
                            mosaicNebulaStreamReader.close();
                        }
                        if (mosaicNebulaStream != null) {
                            mosaicNebulaStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V1_MosaicNebulaSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
