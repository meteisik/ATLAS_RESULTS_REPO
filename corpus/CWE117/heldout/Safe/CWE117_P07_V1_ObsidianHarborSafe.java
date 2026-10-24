import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianHarborSafe {

    public void handleObsidianHarbor() {
        String data;
        data = (new CWE117_P07_V1_ObsidianHarborSafeSource()).readObsidianHarbor();
        Logger obsidianHarborLogger = Logger.getLogger("obsidianHarbor.audit");
        obsidianHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_ObsidianHarborSafeSource {
    public String readObsidianHarbor() {
        String data;
        data = System.getenv("OBSIDIAN_HARBOR_USER");
        return data;
    }
}
