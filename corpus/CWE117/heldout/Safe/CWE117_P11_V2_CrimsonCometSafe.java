import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_CrimsonCometSafe {
    private static int privateFive = 5;

    public void handleCrimsonComet() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("CRIMSON_COMET_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_CrimsonCometSafeSink()).logCrimsonComet(dataHashMap);
    }
}

class CWE117_P11_V2_CrimsonCometSafeSink {
    public void logCrimsonComet(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger crimsonCometLogger = Logger.getLogger("crimsonComet.audit");
        crimsonCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
