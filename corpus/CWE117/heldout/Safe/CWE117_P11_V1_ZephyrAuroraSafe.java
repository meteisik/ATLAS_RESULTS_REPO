import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_ZephyrAuroraSafe {

    public void handleZephyrAurora() {
        String data;
        data = System.getenv("ZEPHYR_AURORA_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_ZephyrAuroraSafeSink()).logZephyrAurora(dataHashMap);
    }
}

class CWE117_P11_V1_ZephyrAuroraSafeSink {
    public void logZephyrAurora(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger zephyrAuroraLogger = Logger.getLogger("zephyrAurora.audit");
        zephyrAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
