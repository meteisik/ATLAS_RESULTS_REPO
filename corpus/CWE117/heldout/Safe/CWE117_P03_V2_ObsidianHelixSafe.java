import java.util.logging.Logger;

public class CWE117_P03_V2_ObsidianHelixSafe {
    private static boolean privateTrue = true;

    private void logObsidianHelix(String data) {
        Logger obsidianHelixLogger = Logger.getLogger("obsidianHelix.audit");
        obsidianHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleObsidianHelix() {
        String data;
        if (privateTrue) {
            data = System.getenv("OBSIDIAN_HELIX_USER");
        } else {
            data = null;
        }
        logObsidianHelix(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
