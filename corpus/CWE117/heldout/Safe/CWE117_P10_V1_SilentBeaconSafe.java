import java.util.logging.Logger;

public class CWE117_P10_V1_SilentBeaconSafe {

    public static String data;

    public void handleSilentBeacon() {
        data = System.getenv("SILENT_BEACON_USER");
        (new CWE117_P10_V1_SilentBeaconSafeSink()).logSilentBeacon();
    }
}

class CWE117_P10_V1_SilentBeaconSafeSink {
    public void logSilentBeacon() {
        String data = CWE117_P10_V1_SilentBeaconSafe.data;
        Logger silentBeaconLogger = Logger.getLogger("silentBeacon.audit");
        silentBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
