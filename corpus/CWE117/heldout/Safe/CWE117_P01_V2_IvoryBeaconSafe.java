import java.util.logging.Logger;

public class CWE117_P01_V2_IvoryBeaconSafe {

    public void handleIvoryBeacon() {
        String data;
        if (5 == 5) {
            data = System.getenv("IVORY_BEACON_USER");
        } else {
            data = null;
        }
        Logger ivoryBeaconLogger = Logger.getLogger("ivoryBeacon.audit");
        ivoryBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
