import java.util.logging.Logger;

public class CWE117_P04_V1_IvoryBeaconSafe {

    private String readIvoryBeacon() {
        String data;
        data = System.getenv("IVORY_BEACON_USER");
        return data;
    }

    public void handleIvoryBeacon() {
        String data = readIvoryBeacon();
        Logger ivoryBeaconLogger = Logger.getLogger("ivoryBeacon.audit");
        ivoryBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
