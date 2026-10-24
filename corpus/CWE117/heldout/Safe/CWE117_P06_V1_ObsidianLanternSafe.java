import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianLanternSafe {

    public void handleObsidianLantern() {
        String data;
        data = System.getenv("OBSIDIAN_LANTERN_USER");
        (new CWE117_P06_V1_ObsidianLanternSafeSink()).logObsidianLantern(data);
    }
}

class CWE117_P06_V1_ObsidianLanternSafeSink {
    public void logObsidianLantern(String data) {
        Logger obsidianLanternLogger = Logger.getLogger("obsidianLantern.audit");
        obsidianLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
