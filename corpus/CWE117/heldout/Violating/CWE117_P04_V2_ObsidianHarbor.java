import java.util.logging.Logger;

public class CWE117_P04_V2_ObsidianHarbor {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String readObsidianHarbor() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_HARBOR_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleObsidianHarbor() {
        String data = readObsidianHarbor();
        Logger obsidianHarborLogger = Logger.getLogger("obsidianHarbor.audit");
        obsidianHarborLogger.info("Login attempt for user " + data);
    }
}
