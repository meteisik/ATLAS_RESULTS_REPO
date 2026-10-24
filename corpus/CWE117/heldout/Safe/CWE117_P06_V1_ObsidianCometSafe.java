import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianCometSafe {

    public void handleObsidianComet() {
        String data;
        data = System.getenv("OBSIDIAN_COMET_USER");
        (new CWE117_P06_V1_ObsidianCometSafeSink()).logObsidianComet(data);
    }
}

class CWE117_P06_V1_ObsidianCometSafeSink {
    public void logObsidianComet(String data) {
        Logger obsidianCometLogger = Logger.getLogger("obsidianComet.audit");
        obsidianCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
