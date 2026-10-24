import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianComet {

    public void handleObsidianComet() {
        String data;
        data = (new CWE117_P07_V1_ObsidianCometSource()).readObsidianComet();
        Logger obsidianCometLogger = Logger.getLogger("obsidianComet.audit");
        obsidianCometLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_ObsidianCometSource {
    public String readObsidianComet() {
        String data;
        data = System.getenv("OBSIDIAN_COMET_USER");
        return data;
    }
}
