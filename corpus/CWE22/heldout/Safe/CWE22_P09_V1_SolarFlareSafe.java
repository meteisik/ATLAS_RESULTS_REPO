import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_SolarFlareSafe {

    static class Container {
        public String containerOne;
    }

    public void openSolarFlare() {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_SolarFlareSafeSink()).readSolarFlare(dataContainer);
    }
}

class CWE22_P09_V1_SolarFlareSafeSink {
    public void readSolarFlare(CWE22_P09_V1_SolarFlareSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
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
                    Logger.getLogger("CWE22_P09_V1_SolarFlareSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P09_V1_SolarFlareSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
