import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianKestrelSafe {

    public void handleObsidianKestrel() {
        String data;
        data = (new CWE117_P07_V1_ObsidianKestrelSafeSource()).readObsidianKestrel();
        Logger obsidianKestrelLogger = Logger.getLogger("obsidianKestrel.audit");
        obsidianKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_ObsidianKestrelSafeSource {
    public String readObsidianKestrel() {
        String data;
        data = System.getenv("OBSIDIAN_KESTREL_USER");
        return data;
    }
}
