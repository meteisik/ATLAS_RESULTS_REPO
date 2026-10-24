import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_SolarQuartz {

    static class Container {
        public String containerOne;
    }

    public void openSolarQuartz() {
        String data;
        if (true) {
            data = System.getenv("SOLAR_QUARTZ_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_SolarQuartzSink()).readSolarQuartz(dataContainer);
    }
}

class CWE22_P09_V2_SolarQuartzSink {
    public void readSolarQuartz(CWE22_P09_V2_SolarQuartz.Container dataContainer) {
        String data = dataContainer.containerOne;
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
                    Logger.getLogger("CWE22_P09_V2_SolarQuartzSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P09_V2_SolarQuartzSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
