import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SilentLanternSafe {

    public void handleSilentLantern() {
        String data;
        data = System.getenv("SILENT_LANTERN_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SilentLanternSafeSink()).logSilentLantern(dataHashMap);
    }
}

class CWE117_P11_V1_SilentLanternSafeSink {
    public void logSilentLantern(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger silentLanternLogger = Logger.getLogger("silentLantern.audit");
        silentLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
