import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SolarFlareSafe {

    public void handleSolarFlare() {
        String data;
        data = System.getenv("SOLAR_FLARE_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SolarFlareSafeSink()).logSolarFlare(dataHashMap);
    }
}

class CWE117_P11_V1_SolarFlareSafeSink {
    public void logSolarFlare(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger solarFlareLogger = Logger.getLogger("solarFlare.audit");
        solarFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
