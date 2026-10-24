import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianHarbor {

    public void handleObsidianHarbor() {
        String data;
        data = System.getenv("OBSIDIAN_HARBOR_USER");
        (new CWE117_P06_V1_ObsidianHarborSink()).logObsidianHarbor(data);
    }
}

class CWE117_P06_V1_ObsidianHarborSink {
    public void logObsidianHarbor(String data) {
        Logger obsidianHarborLogger = Logger.getLogger("obsidianHarbor.audit");
        obsidianHarborLogger.info("Login attempt for user " + data);
    }
}
