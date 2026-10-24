import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_ZephyrPrism {

    public void handleZephyrPrism() {
        String data;
        data = System.getenv("ZEPHYR_PRISM_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_ZephyrPrismSink()).logZephyrPrism(dataHashMap);
    }
}

class CWE117_P11_V1_ZephyrPrismSink {
    public void logZephyrPrism(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger zephyrPrismLogger = Logger.getLogger("zephyrPrism.audit");
        zephyrPrismLogger.info("Login attempt for user " + data);
    }
}
