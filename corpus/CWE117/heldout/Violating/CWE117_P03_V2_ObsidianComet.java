import java.util.logging.Logger;

public class CWE117_P03_V2_ObsidianComet {

    private void logObsidianComet(String data) {
        Logger obsidianCometLogger = Logger.getLogger("obsidianComet.audit");
        obsidianCometLogger.info("Login attempt for user " + data);
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
}
