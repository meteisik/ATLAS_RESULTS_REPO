import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_ZephyrGlintSafe {

    public void handleZephyrGlint() {
        String data;
        data = System.getenv("ZEPHYR_GLINT_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_ZephyrGlintSafeSink()).logZephyrGlint(dataHashMap);
    }
}

class CWE117_P11_V1_ZephyrGlintSafeSink {
    public void logZephyrGlint(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger zephyrGlintLogger = Logger.getLogger("zephyrGlint.audit");
        zephyrGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
