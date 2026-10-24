import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianLantern {

    public void handleObsidianLantern() {
        String data;
        data = System.getenv("OBSIDIAN_LANTERN_USER");
        (new CWE117_P06_V1_ObsidianLanternSink()).logObsidianLantern(data);
    }
}

class CWE117_P06_V1_ObsidianLanternSink {
    public void logObsidianLantern(String data) {
        Logger obsidianLanternLogger = Logger.getLogger("obsidianLantern.audit");
        obsidianLanternLogger.info("Login attempt for user " + data);
    }
}
