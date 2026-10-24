import java.util.logging.Logger;

public class CWE117_P10_V1_SilentBeacon {

    public static String data;

    public void handleSilentBeacon() {
        data = System.getenv("SILENT_BEACON_USER");
        (new CWE117_P10_V1_SilentBeaconSink()).logSilentBeacon();
    }
}

class CWE117_P10_V1_SilentBeaconSink {
    public void logSilentBeacon() {
        String data = CWE117_P10_V1_SilentBeacon.data;
        Logger silentBeaconLogger = Logger.getLogger("silentBeacon.audit");
        silentBeaconLogger.info("Login attempt for user " + data);
    }
}
