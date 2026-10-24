import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VividAurora {

    public void handleVividAurora() {
        String data;
        data = System.getenv("VIVID_AURORA_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VividAuroraSink()).logVividAurora(dataHashMap);
    }
}

class CWE117_P11_V1_VividAuroraSink {
    public void logVividAurora(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger vividAuroraLogger = Logger.getLogger("vividAurora.audit");
        vividAuroraLogger.info("Login attempt for user " + data);
    }
}
