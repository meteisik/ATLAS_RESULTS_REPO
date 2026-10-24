import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SilentBeacon {

    public void handleSilentBeacon() {
        String data;
        data = System.getenv("SILENT_BEACON_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SilentBeaconSink()).logSilentBeacon(dataHashMap);
    }
}

class CWE117_P11_V1_SilentBeaconSink {
    public void logSilentBeacon(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger silentBeaconLogger = Logger.getLogger("silentBeacon.audit");
        silentBeaconLogger.info("Login attempt for user " + data);
    }
}
