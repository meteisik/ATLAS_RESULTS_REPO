import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_SolarQuartzSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openSolarQuartz() {
        String data;
        if (IO.staticFive == 5) {
            data = (new CWE22_P07_V2_SolarQuartzSafeSource()).locateSolarQuartz();
        } else {
            data = null;
        }
        String solarQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File solarQuartzFile = new File(solarQuartzRoot + data);
            FileInputStream solarQuartzStream = null;
            InputStreamReader solarQuartzStreamReader = null;
            BufferedReader solarQuartzReader = null;
            if (solarQuartzFile.exists() && solarQuartzFile.isFile()) {
                try {
                    solarQuartzStream = new FileInputStream(solarQuartzFile);
                    solarQuartzStreamReader = new InputStreamReader(solarQuartzStream, "UTF-8");
                    solarQuartzReader = new BufferedReader(solarQuartzStreamReader);
                    System.out.println(solarQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V2_SolarQuartzSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (solarQuartzReader != null) {
                            solarQuartzReader.close();
                        }
                        if (solarQuartzStreamReader != null) {
                            solarQuartzStreamReader.close();
                        }
                        if (solarQuartzStream != null) {
                            solarQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V2_SolarQuartzSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_SolarQuartzSafeSource {
    public String locateSolarQuartz() {
        String data;
        data = "foo";
        return data;
    }
}
