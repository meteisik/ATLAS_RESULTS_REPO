import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianRavenSafe {

    public void handleObsidianRaven() {
        String data;
        data = (new CWE117_P07_V1_ObsidianRavenSafeSource()).readObsidianRaven();
        Logger obsidianRavenLogger = Logger.getLogger("obsidianRaven.audit");
        obsidianRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_ObsidianRavenSafeSource {
    public String readObsidianRaven() {
        String data;
        data = System.getenv("OBSIDIAN_RAVEN_USER");
        return data;
    }
}
