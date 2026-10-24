import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V2_MosaicOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String locateMosaicOrbit() {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void openMosaicOrbit() {
        String data = locateMosaicOrbit();
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
                    Logger.getLogger("CWE22_P04_V2_MosaicOrbitSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P04_V2_MosaicOrbitSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
