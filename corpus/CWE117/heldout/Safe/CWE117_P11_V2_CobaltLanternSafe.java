import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_CobaltLanternSafe {

    public void handleCobaltLantern() {
        String data;
        if (true) {
            data = System.getenv("COBALT_LANTERN_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_CobaltLanternSafeSink()).logCobaltLantern(dataHashMap);
    }
}

class CWE117_P11_V2_CobaltLanternSafeSink {
    public void logCobaltLantern(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger cobaltLanternLogger = Logger.getLogger("cobaltLantern.audit");
        cobaltLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
