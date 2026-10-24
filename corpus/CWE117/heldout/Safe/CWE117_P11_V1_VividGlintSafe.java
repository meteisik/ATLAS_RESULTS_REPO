import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VividGlintSafe {

    public void handleVividGlint() {
        String data;
        data = System.getenv("VIVID_GLINT_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VividGlintSafeSink()).logVividGlint(dataHashMap);
    }
}

class CWE117_P11_V1_VividGlintSafeSink {
    public void logVividGlint(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger vividGlintLogger = Logger.getLogger("vividGlint.audit");
        vividGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
