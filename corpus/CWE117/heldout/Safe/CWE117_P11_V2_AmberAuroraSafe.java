import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AmberAuroraSafe {

    public void handleAmberAurora() {
        String data;
        if (true) {
            data = System.getenv("AMBER_AURORA_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AmberAuroraSafeSink()).logAmberAurora(dataHashMap);
    }
}

class CWE117_P11_V2_AmberAuroraSafeSink {
    public void logAmberAurora(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger amberAuroraLogger = Logger.getLogger("amberAurora.audit");
        amberAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
