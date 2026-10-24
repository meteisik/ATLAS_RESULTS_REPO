import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianRaven {

    public void handleObsidianRaven() {
        String data;
        data = (new CWE117_P07_V1_ObsidianRavenSource()).readObsidianRaven();
        Logger obsidianRavenLogger = Logger.getLogger("obsidianRaven.audit");
        obsidianRavenLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_ObsidianRavenSource {
    public String readObsidianRaven() {
        String data;
        data = System.getenv("OBSIDIAN_RAVEN_USER");
        return data;
    }
}
