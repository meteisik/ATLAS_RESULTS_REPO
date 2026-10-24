import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryBeacon {

    private void logIvoryBeacon(String data) {
        Logger ivoryBeaconLogger = Logger.getLogger("ivoryBeacon.audit");
        ivoryBeaconLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryBeacon() {
        String data;
        data = System.getenv("IVORY_BEACON_USER");
        logIvoryBeacon(data);
    }
}
