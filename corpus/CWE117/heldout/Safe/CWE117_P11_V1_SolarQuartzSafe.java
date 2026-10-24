import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SolarQuartzSafe {

    public void handleSolarQuartz() {
        String data;
        data = System.getenv("SOLAR_QUARTZ_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SolarQuartzSafeSink()).logSolarQuartz(dataHashMap);
    }
}

class CWE117_P11_V1_SolarQuartzSafeSink {
    public void logSolarQuartz(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger solarQuartzLogger = Logger.getLogger("solarQuartz.audit");
        solarQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
