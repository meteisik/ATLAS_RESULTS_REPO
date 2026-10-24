import java.util.logging.Logger;

public class CWE117_P07_V2_SilentBeaconSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleSilentBeacon() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = (new CWE117_P07_V2_SilentBeaconSafeSource()).readSilentBeacon();
        } else {
            data = null;
        }
        Logger silentBeaconLogger = Logger.getLogger("silentBeacon.audit");
        silentBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SilentBeaconSafeSource {
    public String readSilentBeacon() {
        String data;
        data = System.getenv("SILENT_BEACON_USER");
        return data;
    }
}
