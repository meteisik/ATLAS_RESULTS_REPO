import java.util.logging.Logger;

public class CWE117_P05_V2_ObsidianComet {
    private static int privateFive = 5;

    private String obsidianCometData;

    private void logObsidianComet() {
        String data = obsidianCometData;
        Logger obsidianCometLogger = Logger.getLogger("obsidianComet.audit");
        obsidianCometLogger.info("Login attempt for user " + data);
    }

    public void handleObsidianComet() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("OBSIDIAN_COMET_USER");
        } else {
            data = null;
        }
        obsidianCometData = data;
        logObsidianComet();
    }
}
