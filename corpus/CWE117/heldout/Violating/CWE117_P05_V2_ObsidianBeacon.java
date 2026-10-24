import java.util.logging.Logger;

public class CWE117_P05_V2_ObsidianBeacon {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String obsidianBeaconData;

    private void logObsidianBeacon() {
        String data = obsidianBeaconData;
        Logger obsidianBeaconLogger = Logger.getLogger("obsidianBeacon.audit");
        obsidianBeaconLogger.info("Login attempt for user " + data);
    }

    public void handleObsidianBeacon() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_BEACON_USER");
        } else {
            data = null;
        }
        obsidianBeaconData = data;
        logObsidianBeacon();
    }
}
