import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianHelixSafe {

    public void handleObsidianHelix() {
        String data;
        data = System.getenv("OBSIDIAN_HELIX_USER");
        (new CWE117_P06_V1_ObsidianHelixSafeSink()).logObsidianHelix(data);
    }
}

class CWE117_P06_V1_ObsidianHelixSafeSink {
    public void logObsidianHelix(String data) {
        Logger obsidianHelixLogger = Logger.getLogger("obsidianHelix.audit");
        obsidianHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
