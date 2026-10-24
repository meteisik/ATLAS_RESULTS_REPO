import java.util.logging.Logger;

public class CWE117_P03_V2_ObsidianBeaconSafe {

    private void logObsidianBeacon(String data) {
        Logger obsidianBeaconLogger = Logger.getLogger("obsidianBeacon.audit");
        obsidianBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleObsidianBeacon() {
        String data;
        if (true) {
            data = System.getenv("OBSIDIAN_BEACON_USER");
        } else {
            data = null;
        }
        logObsidianBeacon(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
