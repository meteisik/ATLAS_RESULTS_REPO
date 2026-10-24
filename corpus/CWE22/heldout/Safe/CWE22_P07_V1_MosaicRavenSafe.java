import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V1_MosaicRavenSafe {

    public void openMosaicRaven() {
        String data;
        data = (new CWE22_P07_V1_MosaicRavenSafeSource()).locateMosaicRaven();
        String mosaicRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File mosaicRavenFile = new File(mosaicRavenRoot + data);
            FileInputStream mosaicRavenStream = null;
            InputStreamReader mosaicRavenStreamReader = null;
            BufferedReader mosaicRavenReader = null;
            if (mosaicRavenFile.exists() && mosaicRavenFile.isFile()) {
                try {
                    mosaicRavenStream = new FileInputStream(mosaicRavenFile);
                    mosaicRavenStreamReader = new InputStreamReader(mosaicRavenStream, "UTF-8");
                    mosaicRavenReader = new BufferedReader(mosaicRavenStreamReader);
                    System.out.println(mosaicRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V1_MosaicRavenSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (mosaicRavenReader != null) {
                            mosaicRavenReader.close();
                        }
                        if (mosaicRavenStreamReader != null) {
                            mosaicRavenStreamReader.close();
                        }
                        if (mosaicRavenStream != null) {
                            mosaicRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V1_MosaicRavenSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V1_MosaicRavenSafeSource {
    public String locateMosaicRaven() {
        String data;
        data = "foo";
        return data;
    }
}
