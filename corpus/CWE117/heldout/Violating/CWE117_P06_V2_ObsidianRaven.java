import java.util.logging.Logger;

public class CWE117_P06_V2_ObsidianRaven {

    public void handleObsidianRaven() {
        String data;
        if (true) {
            data = System.getenv("OBSIDIAN_RAVEN_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_ObsidianRavenSink()).logObsidianRaven(data);
    }
}

class CWE117_P06_V2_ObsidianRavenSink {
    public void logObsidianRaven(String data) {
        Logger obsidianRavenLogger = Logger.getLogger("obsidianRaven.audit");
        obsidianRavenLogger.info("Login attempt for user " + data);
    }
}
