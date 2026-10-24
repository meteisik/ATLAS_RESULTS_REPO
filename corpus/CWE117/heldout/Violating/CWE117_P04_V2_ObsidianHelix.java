import java.util.logging.Logger;

public class CWE117_P04_V2_ObsidianHelix {
    private static int privateFive = 5;

    private String readObsidianHelix() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("OBSIDIAN_HELIX_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleObsidianHelix() {
        String data = readObsidianHelix();
        Logger obsidianHelixLogger = Logger.getLogger("obsidianHelix.audit");
        obsidianHelixLogger.info("Login attempt for user " + data);
    }
}
