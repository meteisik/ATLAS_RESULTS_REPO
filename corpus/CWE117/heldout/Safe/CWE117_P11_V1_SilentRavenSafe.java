import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SilentRavenSafe {

    public void handleSilentRaven() {
        String data;
        data = System.getenv("SILENT_RAVEN_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SilentRavenSafeSink()).logSilentRaven(dataHashMap);
    }
}

class CWE117_P11_V1_SilentRavenSafeSink {
    public void logSilentRaven(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger silentRavenLogger = Logger.getLogger("silentRaven.audit");
        silentRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
