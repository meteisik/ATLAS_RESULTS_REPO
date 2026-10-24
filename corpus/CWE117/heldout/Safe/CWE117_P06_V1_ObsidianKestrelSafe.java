import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianKestrelSafe {

    public void handleObsidianKestrel() {
        String data;
        data = System.getenv("OBSIDIAN_KESTREL_USER");
        (new CWE117_P06_V1_ObsidianKestrelSafeSink()).logObsidianKestrel(data);
    }
}

class CWE117_P06_V1_ObsidianKestrelSafeSink {
    public void logObsidianKestrel(String data) {
        Logger obsidianKestrelLogger = Logger.getLogger("obsidianKestrel.audit");
        obsidianKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
