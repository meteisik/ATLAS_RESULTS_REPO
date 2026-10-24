import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianCometSafe {

    public void handleObsidianComet() {
        String data;
        data = (new CWE117_P07_V1_ObsidianCometSafeSource()).readObsidianComet();
        Logger obsidianCometLogger = Logger.getLogger("obsidianComet.audit");
        obsidianCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_ObsidianCometSafeSource {
    public String readObsidianComet() {
        String data;
        data = System.getenv("OBSIDIAN_COMET_USER");
        return data;
    }
}
