import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SilentHarborSafe {

    public void handleSilentHarbor() {
        String data;
        data = System.getenv("SILENT_HARBOR_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SilentHarborSafeSink()).logSilentHarbor(dataHashMap);
    }
}

class CWE117_P11_V1_SilentHarborSafeSink {
    public void logSilentHarbor(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger silentHarborLogger = Logger.getLogger("silentHarbor.audit");
        silentHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
