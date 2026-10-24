import java.util.logging.Logger;

public class CWE117_P07_V2_SilentBeacon {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleSilentBeacon() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = (new CWE117_P07_V2_SilentBeaconSource()).readSilentBeacon();
        } else {
            data = null;
        }
        Logger silentBeaconLogger = Logger.getLogger("silentBeacon.audit");
        silentBeaconLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SilentBeaconSource {
    public String readSilentBeacon() {
        String data;
        data = System.getenv("SILENT_BEACON_USER");
        return data;
    }
}
