import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SaffronQuartzSafe {

    public void handleSaffronQuartz() {
        String data;
        data = System.getenv("SAFFRON_QUARTZ_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SaffronQuartzSafeSink()).logSaffronQuartz(dataHashMap);
    }
}

class CWE117_P11_V1_SaffronQuartzSafeSink {
    public void logSaffronQuartz(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger saffronQuartzLogger = Logger.getLogger("saffronQuartz.audit");
        saffronQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
