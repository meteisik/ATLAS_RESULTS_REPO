import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianHelixSafe {

    public void handleObsidianHelix() {
        String data;
        data = (new CWE117_P07_V1_ObsidianHelixSafeSource()).readObsidianHelix();
        Logger obsidianHelixLogger = Logger.getLogger("obsidianHelix.audit");
        obsidianHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_ObsidianHelixSafeSource {
    public String readObsidianHelix() {
        String data;
        data = System.getenv("OBSIDIAN_HELIX_USER");
        return data;
    }
}
