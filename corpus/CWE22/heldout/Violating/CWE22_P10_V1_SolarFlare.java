import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V1_SolarFlare {
    public static String data;

    public void openSolarFlare() {
        data = System.getenv("SOLAR_FLARE_PATH");
        (new CWE22_P10_V1_SolarFlareSink()).readSolarFlare();
    }
}

class CWE22_P10_V1_SolarFlareSink {
    public void readSolarFlare() {
        String data = CWE22_P10_V1_SolarFlare.data;
        String solarFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File solarFlareFile = new File(solarFlareRoot + data);
            FileInputStream solarFlareStream = null;
            InputStreamReader solarFlareStreamReader = null;
            BufferedReader solarFlareReader = null;
            if (solarFlareFile.exists() && solarFlareFile.isFile()) {
                try {
                    solarFlareStream = new FileInputStream(solarFlareFile);
                    solarFlareStreamReader = new InputStreamReader(solarFlareStream, "UTF-8");
                    solarFlareReader = new BufferedReader(solarFlareStreamReader);
                    System.out.println(solarFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V1_SolarFlareSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (solarFlareReader != null) {
                            solarFlareReader.close();
                        }
                        if (solarFlareStreamReader != null) {
                            solarFlareStreamReader.close();
                        }
                        if (solarFlareStream != null) {
                            solarFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V1_SolarFlareSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
