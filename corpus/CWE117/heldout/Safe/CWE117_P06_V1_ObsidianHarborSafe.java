import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianHarborSafe {

    public void handleObsidianHarbor() {
        String data;
        data = System.getenv("OBSIDIAN_HARBOR_USER");
        (new CWE117_P06_V1_ObsidianHarborSafeSink()).logObsidianHarbor(data);
    }
}

class CWE117_P06_V1_ObsidianHarborSafeSink {
    public void logObsidianHarbor(String data) {
        Logger obsidianHarborLogger = Logger.getLogger("obsidianHarbor.audit");
        obsidianHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
