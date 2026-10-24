import java.util.logging.Logger;

public class CWE117_P08_V2_SilentBeaconSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleSilentBeacon() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SILENT_BEACON_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SilentBeaconSafeSink()).logSilentBeacon(dataArray);
    }
}

class CWE117_P08_V2_SilentBeaconSafeSink {
    public void logSilentBeacon(String[] dataArray) {
        String data = dataArray[2];
        Logger silentBeaconLogger = Logger.getLogger("silentBeacon.audit");
        silentBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
