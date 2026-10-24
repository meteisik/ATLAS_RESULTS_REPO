import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V1_SolarQuartzSafe {
    public static String data;

    public void openSolarQuartz() {
        data = "foo";
        (new CWE22_P10_V1_SolarQuartzSafeSink()).readSolarQuartz();
    }
}

class CWE22_P10_V1_SolarQuartzSafeSink {
    public void readSolarQuartz() {
        String data = CWE22_P10_V1_SolarQuartzSafe.data;
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
                    Logger.getLogger("CWE22_P10_V1_SolarQuartzSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P10_V1_SolarQuartzSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
