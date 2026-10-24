import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryBeacon {

    private String ivoryBeaconData;

    private void logIvoryBeacon() {
        String data = ivoryBeaconData;
        Logger ivoryBeaconLogger = Logger.getLogger("ivoryBeacon.audit");
        ivoryBeaconLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryBeacon() {
        String data;
        data = System.getenv("IVORY_BEACON_USER");
        ivoryBeaconData = data;
        logIvoryBeacon();
    }
}
