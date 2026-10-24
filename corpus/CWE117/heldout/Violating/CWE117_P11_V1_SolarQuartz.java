import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SolarQuartz {

    public void handleSolarQuartz() {
        String data;
        data = System.getenv("SOLAR_QUARTZ_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SolarQuartzSink()).logSolarQuartz(dataHashMap);
    }
}

class CWE117_P11_V1_SolarQuartzSink {
    public void logSolarQuartz(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger solarQuartzLogger = Logger.getLogger("solarQuartz.audit");
        solarQuartzLogger.info("Login attempt for user " + data);
    }
}
