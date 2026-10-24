import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_ZephyrSignal {

    public void handleZephyrSignal() {
        String data;
        data = System.getenv("ZEPHYR_SIGNAL_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_ZephyrSignalSink()).logZephyrSignal(dataHashMap);
    }
}

class CWE117_P11_V1_ZephyrSignalSink {
    public void logZephyrSignal(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger zephyrSignalLogger = Logger.getLogger("zephyrSignal.audit");
        zephyrSignalLogger.info("Login attempt for user " + data);
    }
}
