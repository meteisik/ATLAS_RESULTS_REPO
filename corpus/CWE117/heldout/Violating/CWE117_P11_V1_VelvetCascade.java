import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VelvetCascade {

    public void handleVelvetCascade() {
        String data;
        data = System.getenv("VELVET_CASCADE_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VelvetCascadeSink()).logVelvetCascade(dataHashMap);
    }
}

class CWE117_P11_V1_VelvetCascadeSink {
    public void logVelvetCascade(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger velvetCascadeLogger = Logger.getLogger("velvetCascade.audit");
        velvetCascadeLogger.info("Login attempt for user " + data);
    }
}
