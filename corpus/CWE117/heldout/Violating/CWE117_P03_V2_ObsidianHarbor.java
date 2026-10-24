import java.util.logging.Logger;

public class CWE117_P03_V2_ObsidianHarbor {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private void logObsidianHarbor(String data) {
        Logger obsidianHarborLogger = Logger.getLogger("obsidianHarbor.audit");
        obsidianHarborLogger.info("Login attempt for user " + data);
    }

    public void handleObsidianHarbor() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("OBSIDIAN_HARBOR_USER");
        } else {
            data = null;
        }
        logObsidianHarbor(data);
    }
}
