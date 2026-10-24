import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianBeaconSafe {

    public void handleObsidianBeacon() {
        String data;
        data = System.getenv("OBSIDIAN_BEACON_USER");
        (new CWE117_P06_V1_ObsidianBeaconSafeSink()).logObsidianBeacon(data);
    }
}

class CWE117_P06_V1_ObsidianBeaconSafeSink {
    public void logObsidianBeacon(String data) {
        Logger obsidianBeaconLogger = Logger.getLogger("obsidianBeacon.audit");
        obsidianBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
