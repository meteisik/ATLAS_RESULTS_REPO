import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AmberAurora {

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
        (new CWE117_P11_V2_AmberAuroraSink()).logAmberAurora(dataHashMap);
    }
}

class CWE117_P11_V2_AmberAuroraSink {
    public void logAmberAurora(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger amberAuroraLogger = Logger.getLogger("amberAurora.audit");
        amberAuroraLogger.info("Login attempt for user " + data);
    }
}
