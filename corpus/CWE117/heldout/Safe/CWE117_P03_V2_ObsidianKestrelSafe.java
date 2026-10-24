import java.util.logging.Logger;

public class CWE117_P03_V2_ObsidianKestrelSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private void logObsidianKestrel(String data) {
        Logger obsidianKestrelLogger = Logger.getLogger("obsidianKestrel.audit");
        obsidianKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleObsidianKestrel() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_KESTREL_USER");
        } else {
            data = null;
        }
        logObsidianKestrel(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
