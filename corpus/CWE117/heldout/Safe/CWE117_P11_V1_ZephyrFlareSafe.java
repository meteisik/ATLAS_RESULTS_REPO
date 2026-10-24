import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_ZephyrFlareSafe {

    public void handleZephyrFlare() {
        String data;
        data = System.getenv("ZEPHYR_FLARE_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_ZephyrFlareSafeSink()).logZephyrFlare(dataHashMap);
    }
}

class CWE117_P11_V1_ZephyrFlareSafeSink {
    public void logZephyrFlare(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger zephyrFlareLogger = Logger.getLogger("zephyrFlare.audit");
        zephyrFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
