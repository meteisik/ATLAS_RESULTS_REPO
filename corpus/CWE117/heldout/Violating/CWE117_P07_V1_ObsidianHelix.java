import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianHelix {

    public void handleObsidianHelix() {
        String data;
        data = (new CWE117_P07_V1_ObsidianHelixSource()).readObsidianHelix();
        Logger obsidianHelixLogger = Logger.getLogger("obsidianHelix.audit");
        obsidianHelixLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_ObsidianHelixSource {
    public String readObsidianHelix() {
        String data;
        data = System.getenv("OBSIDIAN_HELIX_USER");
        return data;
    }
}
