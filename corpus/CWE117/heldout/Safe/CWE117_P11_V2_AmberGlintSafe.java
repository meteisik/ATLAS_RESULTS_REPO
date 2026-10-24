import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AmberGlintSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleAmberGlint() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AMBER_GLINT_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AmberGlintSafeSink()).logAmberGlint(dataHashMap);
    }
}

class CWE117_P11_V2_AmberGlintSafeSink {
    public void logAmberGlint(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger amberGlintLogger = Logger.getLogger("amberGlint.audit");
        amberGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
