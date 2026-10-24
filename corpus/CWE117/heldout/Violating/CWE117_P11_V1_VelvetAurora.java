import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VelvetAurora {

    public void handleVelvetAurora() {
        String data;
        data = System.getenv("VELVET_AURORA_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VelvetAuroraSink()).logVelvetAurora(dataHashMap);
    }
}

class CWE117_P11_V1_VelvetAuroraSink {
    public void logVelvetAurora(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger velvetAuroraLogger = Logger.getLogger("velvetAurora.audit");
        velvetAuroraLogger.info("Login attempt for user " + data);
    }
}
