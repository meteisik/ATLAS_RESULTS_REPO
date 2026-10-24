import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SilentBeaconSafe {

    public void handleSilentBeacon() {
        String data;
        data = System.getenv("SILENT_BEACON_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SilentBeaconSafeSink()).logSilentBeacon(dataHashMap);
    }
}

class CWE117_P11_V1_SilentBeaconSafeSink {
    public void logSilentBeacon(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger silentBeaconLogger = Logger.getLogger("silentBeacon.audit");
        silentBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
