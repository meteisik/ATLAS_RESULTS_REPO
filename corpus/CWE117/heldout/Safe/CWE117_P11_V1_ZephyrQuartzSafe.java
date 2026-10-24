import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_ZephyrQuartzSafe {

    public void handleZephyrQuartz() {
        String data;
        data = System.getenv("ZEPHYR_QUARTZ_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_ZephyrQuartzSafeSink()).logZephyrQuartz(dataHashMap);
    }
}

class CWE117_P11_V1_ZephyrQuartzSafeSink {
    public void logZephyrQuartz(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger zephyrQuartzLogger = Logger.getLogger("zephyrQuartz.audit");
        zephyrQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
