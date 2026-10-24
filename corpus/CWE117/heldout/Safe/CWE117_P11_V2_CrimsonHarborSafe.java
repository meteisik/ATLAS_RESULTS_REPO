import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_CrimsonHarborSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleCrimsonHarbor() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("CRIMSON_HARBOR_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_CrimsonHarborSafeSink()).logCrimsonHarbor(dataHashMap);
    }
}

class CWE117_P11_V2_CrimsonHarborSafeSink {
    public void logCrimsonHarbor(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger crimsonHarborLogger = Logger.getLogger("crimsonHarbor.audit");
        crimsonHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
