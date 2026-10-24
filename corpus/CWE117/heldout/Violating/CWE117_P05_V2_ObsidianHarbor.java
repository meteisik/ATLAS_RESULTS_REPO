import java.util.logging.Logger;

public class CWE117_P05_V2_ObsidianHarbor {
    private static boolean privateReturnsTrue() { return true; }

    private String obsidianHarborData;

    private void logObsidianHarbor() {
        String data = obsidianHarborData;
        Logger obsidianHarborLogger = Logger.getLogger("obsidianHarbor.audit");
        obsidianHarborLogger.info("Login attempt for user " + data);
    }

    public void handleObsidianHarbor() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("OBSIDIAN_HARBOR_USER");
        } else {
            data = null;
        }
        obsidianHarborData = data;
        logObsidianHarbor();
    }
}
