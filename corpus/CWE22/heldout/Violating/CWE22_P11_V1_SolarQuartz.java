import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_SolarQuartz {

    public void openSolarQuartz() {
        String data;
        data = System.getenv("SOLAR_QUARTZ_PATH");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_SolarQuartzSink()).readSolarQuartz(dataHashMap);
    }
}

class CWE22_P11_V1_SolarQuartzSink {
    public void readSolarQuartz(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
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
                    Logger.getLogger("CWE22_P11_V1_SolarQuartzSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P11_V1_SolarQuartzSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
