import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_CrimsonBeaconSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleCrimsonBeacon() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_BEACON_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_CrimsonBeaconSafeSink()).logCrimsonBeacon(dataHashMap);
    }
}

class CWE117_P11_V2_CrimsonBeaconSafeSink {
    public void logCrimsonBeacon(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger crimsonBeaconLogger = Logger.getLogger("crimsonBeacon.audit");
        crimsonBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
