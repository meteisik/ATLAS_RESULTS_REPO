import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_SolarFlare {

    public void openSolarFlare() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("SOLAR_FLARE_PATH");
            break;
        default:
            data = null;
            break;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_SolarFlareSink()).readSolarFlare(dataArray);
    }
}

class CWE22_P08_V2_SolarFlareSink {
    public void readSolarFlare(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V2_SolarFlareSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V2_SolarFlareSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
