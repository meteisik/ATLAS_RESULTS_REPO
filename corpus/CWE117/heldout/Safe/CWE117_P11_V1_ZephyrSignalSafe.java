import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_ZephyrSignalSafe {

    public void handleZephyrSignal() {
        String data;
        data = System.getenv("ZEPHYR_SIGNAL_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_ZephyrSignalSafeSink()).logZephyrSignal(dataHashMap);
    }
}

class CWE117_P11_V1_ZephyrSignalSafeSink {
    public void logZephyrSignal(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger zephyrSignalLogger = Logger.getLogger("zephyrSignal.audit");
        zephyrSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
