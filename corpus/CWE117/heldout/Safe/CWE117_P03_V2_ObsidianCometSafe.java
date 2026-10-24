import java.util.logging.Logger;

public class CWE117_P03_V2_ObsidianCometSafe {

    private void logObsidianComet(String data) {
        Logger obsidianCometLogger = Logger.getLogger("obsidianComet.audit");
        obsidianCometLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleObsidianComet() {
        String data;
        if (5 == 5) {
            data = System.getenv("OBSIDIAN_COMET_USER");
        } else {
            data = null;
        }
        logObsidianComet(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
