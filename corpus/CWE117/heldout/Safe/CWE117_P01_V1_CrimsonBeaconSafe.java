import java.util.logging.Logger;

public class CWE117_P01_V1_CrimsonBeaconSafe {

    public void handleCrimsonBeacon() {
        String data;
        data = System.getenv("CRIMSON_BEACON_USER");
        Logger crimsonBeaconLogger = Logger.getLogger("crimsonBeacon.audit");
        crimsonBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
