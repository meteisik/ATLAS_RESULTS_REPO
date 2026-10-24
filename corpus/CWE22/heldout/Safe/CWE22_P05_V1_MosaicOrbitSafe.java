import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V1_MosaicOrbitSafe {
    private String mosaicOrbitData;

    private void readMosaicOrbit() {
        String data = mosaicOrbitData;
        String mosaicOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File mosaicOrbitFile = new File(mosaicOrbitRoot + data);
            FileInputStream mosaicOrbitStream = null;
            InputStreamReader mosaicOrbitStreamReader = null;
            BufferedReader mosaicOrbitReader = null;
            if (mosaicOrbitFile.exists() && mosaicOrbitFile.isFile()) {
                try {
                    mosaicOrbitStream = new FileInputStream(mosaicOrbitFile);
                    mosaicOrbitStreamReader = new InputStreamReader(mosaicOrbitStream, "UTF-8");
                    mosaicOrbitReader = new BufferedReader(mosaicOrbitStreamReader);
                    System.out.println(mosaicOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V1_MosaicOrbitSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (mosaicOrbitReader != null) {
                            mosaicOrbitReader.close();
                        }
                        if (mosaicOrbitStreamReader != null) {
                            mosaicOrbitStreamReader.close();
                        }
                        if (mosaicOrbitStream != null) {
                            mosaicOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V1_MosaicOrbitSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openMosaicOrbit() {
        String data;
        data = "foo";
        mosaicOrbitData = data;
        readMosaicOrbit();
    }
}
