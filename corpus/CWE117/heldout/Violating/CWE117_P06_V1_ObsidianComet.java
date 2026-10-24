import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianComet {

    public void handleObsidianComet() {
        String data;
        data = System.getenv("OBSIDIAN_COMET_USER");
        (new CWE117_P06_V1_ObsidianCometSink()).logObsidianComet(data);
    }
}

class CWE117_P06_V1_ObsidianCometSink {
    public void logObsidianComet(String data) {
        Logger obsidianCometLogger = Logger.getLogger("obsidianComet.audit");
        obsidianCometLogger.info("Login attempt for user " + data);
    }
}
