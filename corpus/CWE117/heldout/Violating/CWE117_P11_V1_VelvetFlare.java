import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VelvetFlare {

    public void handleVelvetFlare() {
        String data;
        data = System.getenv("VELVET_FLARE_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VelvetFlareSink()).logVelvetFlare(dataHashMap);
    }
}

class CWE117_P11_V1_VelvetFlareSink {
    public void logVelvetFlare(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger velvetFlareLogger = Logger.getLogger("velvetFlare.audit");
        velvetFlareLogger.info("Login attempt for user " + data);
    }
}
