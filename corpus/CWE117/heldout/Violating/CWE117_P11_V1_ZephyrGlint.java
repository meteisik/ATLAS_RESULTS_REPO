import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_ZephyrGlint {

    public void handleZephyrGlint() {
        String data;
        data = System.getenv("ZEPHYR_GLINT_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_ZephyrGlintSink()).logZephyrGlint(dataHashMap);
    }
}

class CWE117_P11_V1_ZephyrGlintSink {
    public void logZephyrGlint(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger zephyrGlintLogger = Logger.getLogger("zephyrGlint.audit");
        zephyrGlintLogger.info("Login attempt for user " + data);
    }
}
