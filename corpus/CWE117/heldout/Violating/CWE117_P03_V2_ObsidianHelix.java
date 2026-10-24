import java.util.logging.Logger;

public class CWE117_P03_V2_ObsidianHelix {
    private static boolean privateTrue = true;

    private void logObsidianHelix(String data) {
        Logger obsidianHelixLogger = Logger.getLogger("obsidianHelix.audit");
        obsidianHelixLogger.info("Login attempt for user " + data);
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
}
