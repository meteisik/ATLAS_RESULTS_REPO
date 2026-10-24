import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_ZephyrSundialSafe {

    public void handleZephyrSundial() {
        String data;
        data = System.getenv("ZEPHYR_SUNDIAL_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_ZephyrSundialSafeSink()).logZephyrSundial(dataHashMap);
    }
}

class CWE117_P11_V1_ZephyrSundialSafeSink {
    public void logZephyrSundial(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger zephyrSundialLogger = Logger.getLogger("zephyrSundial.audit");
        zephyrSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
