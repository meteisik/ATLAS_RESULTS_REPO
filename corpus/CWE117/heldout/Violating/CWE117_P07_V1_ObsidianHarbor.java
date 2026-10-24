import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianHarbor {

    public void handleObsidianHarbor() {
        String data;
        data = (new CWE117_P07_V1_ObsidianHarborSource()).readObsidianHarbor();
        Logger obsidianHarborLogger = Logger.getLogger("obsidianHarbor.audit");
        obsidianHarborLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_ObsidianHarborSource {
    public String readObsidianHarbor() {
        String data;
        data = System.getenv("OBSIDIAN_HARBOR_USER");
        return data;
    }
}
