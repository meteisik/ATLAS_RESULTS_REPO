import java.util.logging.Logger;

public class CWE117_P05_V2_OnyxBeacon {

    private String onyxBeaconData;

    private void logOnyxBeacon() {
        String data = onyxBeaconData;
        Logger onyxBeaconLogger = Logger.getLogger("onyxBeacon.audit");
        onyxBeaconLogger.info("Login attempt for user " + data);
    }

    public void handleOnyxBeacon() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ONYX_BEACON_USER");
        }
        onyxBeaconData = data;
        logOnyxBeacon();
    }
}
