import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_SolarFlareSafe {

    public void openSolarFlare() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_SolarFlareSafeSink()).readSolarFlare(dataHashMap);
    }
}

class CWE22_P11_V1_SolarFlareSafeSink {
    public void readSolarFlare(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
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
                    Logger.getLogger("CWE22_P11_V1_SolarFlareSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P11_V1_SolarFlareSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
