import java.util.logging.Logger;

public class CWE117_P04_V2_ObsidianCometSafe {
    private static boolean privateTrue = true;

    private String readObsidianComet() {
        String data;
        if (privateTrue) {
            data = System.getenv("OBSIDIAN_COMET_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleObsidianComet() {
        String data = readObsidianComet();
        Logger obsidianCometLogger = Logger.getLogger("obsidianComet.audit");
        obsidianCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
