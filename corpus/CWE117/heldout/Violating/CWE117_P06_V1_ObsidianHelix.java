import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianHelix {

    public void handleObsidianHelix() {
        String data;
        data = System.getenv("OBSIDIAN_HELIX_USER");
        (new CWE117_P06_V1_ObsidianHelixSink()).logObsidianHelix(data);
    }
}

class CWE117_P06_V1_ObsidianHelixSink {
    public void logObsidianHelix(String data) {
        Logger obsidianHelixLogger = Logger.getLogger("obsidianHelix.audit");
        obsidianHelixLogger.info("Login attempt for user " + data);
    }
}
