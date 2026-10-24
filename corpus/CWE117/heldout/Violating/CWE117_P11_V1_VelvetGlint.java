import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VelvetGlint {

    public void handleVelvetGlint() {
        String data;
        data = System.getenv("VELVET_GLINT_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VelvetGlintSink()).logVelvetGlint(dataHashMap);
    }
}

class CWE117_P11_V1_VelvetGlintSink {
    public void logVelvetGlint(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger velvetGlintLogger = Logger.getLogger("velvetGlint.audit");
        velvetGlintLogger.info("Login attempt for user " + data);
    }
}
