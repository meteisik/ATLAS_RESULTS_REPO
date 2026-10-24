import java.util.logging.Logger;

public class CWE117_P03_V2_ObsidianLanternSafe {
    private static int privateFive = 5;

    private void logObsidianLantern(String data) {
        Logger obsidianLanternLogger = Logger.getLogger("obsidianLantern.audit");
        obsidianLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleObsidianLantern() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("OBSIDIAN_LANTERN_USER");
        } else {
            data = null;
        }
        logObsidianLantern(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
