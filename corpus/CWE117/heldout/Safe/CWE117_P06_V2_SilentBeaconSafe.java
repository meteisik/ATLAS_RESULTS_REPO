import java.util.logging.Logger;

public class CWE117_P06_V2_SilentBeaconSafe {

    public void handleSilentBeacon() {
        String data;
        if (true) {
            data = System.getenv("SILENT_BEACON_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SilentBeaconSafeSink()).logSilentBeacon(data);
    }
}

class CWE117_P06_V2_SilentBeaconSafeSink {
    public void logSilentBeacon(String data) {
        Logger silentBeaconLogger = Logger.getLogger("silentBeacon.audit");
        silentBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
