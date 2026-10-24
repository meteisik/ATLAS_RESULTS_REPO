import java.util.logging.Logger;

public class CWE117_P06_V2_ObsidianRavenSafe {

    public void handleObsidianRaven() {
        String data;
        if (true) {
            data = System.getenv("OBSIDIAN_RAVEN_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_ObsidianRavenSafeSink()).logObsidianRaven(data);
    }
}

class CWE117_P06_V2_ObsidianRavenSafeSink {
    public void logObsidianRaven(String data) {
        Logger obsidianRavenLogger = Logger.getLogger("obsidianRaven.audit");
        obsidianRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
