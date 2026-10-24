import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VelvetGlintSafe {

    public void handleVelvetGlint() {
        String data;
        data = System.getenv("VELVET_GLINT_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VelvetGlintSafeSink()).logVelvetGlint(dataHashMap);
    }
}

class CWE117_P11_V1_VelvetGlintSafeSink {
    public void logVelvetGlint(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger velvetGlintLogger = Logger.getLogger("velvetGlint.audit");
        velvetGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
