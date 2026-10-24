import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianLanternSafe {

    public void handleObsidianLantern() {
        String data;
        data = (new CWE117_P07_V1_ObsidianLanternSafeSource()).readObsidianLantern();
        Logger obsidianLanternLogger = Logger.getLogger("obsidianLantern.audit");
        obsidianLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_ObsidianLanternSafeSource {
    public String readObsidianLantern() {
        String data;
        data = System.getenv("OBSIDIAN_LANTERN_USER");
        return data;
    }
}
