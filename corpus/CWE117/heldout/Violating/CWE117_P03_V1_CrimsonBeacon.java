import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonBeacon {

    private void logCrimsonBeacon(String data) {
        Logger crimsonBeaconLogger = Logger.getLogger("crimsonBeacon.audit");
        crimsonBeaconLogger.info("Login attempt for user " + data);
    }

    public void handleCrimsonBeacon() {
        String data;
        data = System.getenv("CRIMSON_BEACON_USER");
        logCrimsonBeacon(data);
    }
}
