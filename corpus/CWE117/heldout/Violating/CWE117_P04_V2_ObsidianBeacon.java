import java.util.logging.Logger;

public class CWE117_P04_V2_ObsidianBeacon {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String readObsidianBeacon() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("OBSIDIAN_BEACON_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleObsidianBeacon() {
        String data = readObsidianBeacon();
        Logger obsidianBeaconLogger = Logger.getLogger("obsidianBeacon.audit");
        obsidianBeaconLogger.info("Login attempt for user " + data);
    }
}
