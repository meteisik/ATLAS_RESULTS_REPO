import java.util.logging.Logger;

public class CWE117_P05_V2_ObsidianRavenSafe {

    private String obsidianRavenData;

    private void logObsidianRaven() {
        String data = obsidianRavenData;
        Logger obsidianRavenLogger = Logger.getLogger("obsidianRaven.audit");
        obsidianRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleObsidianRaven() {
        String data;
        while (true) {
            data = System.getenv("OBSIDIAN_RAVEN_USER");
            break;
        }
        obsidianRavenData = data;
        logObsidianRaven();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
