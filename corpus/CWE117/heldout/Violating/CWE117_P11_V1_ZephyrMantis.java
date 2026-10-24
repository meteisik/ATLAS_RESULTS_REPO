import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_ZephyrMantis {

    public void handleZephyrMantis() {
        String data;
        data = System.getenv("ZEPHYR_MANTIS_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_ZephyrMantisSink()).logZephyrMantis(dataHashMap);
    }
}

class CWE117_P11_V1_ZephyrMantisSink {
    public void logZephyrMantis(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger zephyrMantisLogger = Logger.getLogger("zephyrMantis.audit");
        zephyrMantisLogger.info("Login attempt for user " + data);
    }
}
