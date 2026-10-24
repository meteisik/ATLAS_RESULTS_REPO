import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_CobaltRavenSafe {
    private static boolean privateTrue = true;

    public void handleCobaltRaven() {
        String data;
        if (privateTrue) {
            data = System.getenv("COBALT_RAVEN_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_CobaltRavenSafeSink()).logCobaltRaven(dataHashMap);
    }
}

class CWE117_P11_V2_CobaltRavenSafeSink {
    public void logCobaltRaven(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger cobaltRavenLogger = Logger.getLogger("cobaltRaven.audit");
        cobaltRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
