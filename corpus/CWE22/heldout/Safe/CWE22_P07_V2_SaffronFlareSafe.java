import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_SaffronFlareSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openSaffronFlare() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = (new CWE22_P07_V2_SaffronFlareSafeSource()).locateSaffronFlare();
        } else {
            data = null;
        }
        String saffronFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronFlareFile = new File(saffronFlareRoot + data);
            FileInputStream saffronFlareStream = null;
            InputStreamReader saffronFlareStreamReader = null;
            BufferedReader saffronFlareReader = null;
            if (saffronFlareFile.exists() && saffronFlareFile.isFile()) {
                try {
                    saffronFlareStream = new FileInputStream(saffronFlareFile);
                    saffronFlareStreamReader = new InputStreamReader(saffronFlareStream, "UTF-8");
                    saffronFlareReader = new BufferedReader(saffronFlareStreamReader);
                    System.out.println(saffronFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V2_SaffronFlareSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronFlareReader != null) {
                            saffronFlareReader.close();
                        }
                        if (saffronFlareStreamReader != null) {
                            saffronFlareStreamReader.close();
                        }
                        if (saffronFlareStream != null) {
                            saffronFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V2_SaffronFlareSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_SaffronFlareSafeSource {
    public String locateSaffronFlare() {
        String data;
        data = "foo";
        return data;
    }
}
