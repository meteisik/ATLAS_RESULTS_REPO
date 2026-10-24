import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianLantern {

    public void handleObsidianLantern() {
        String data;
        data = (new CWE117_P07_V1_ObsidianLanternSource()).readObsidianLantern();
        Logger obsidianLanternLogger = Logger.getLogger("obsidianLantern.audit");
        obsidianLanternLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_ObsidianLanternSource {
    public String readObsidianLantern() {
        String data;
        data = System.getenv("OBSIDIAN_LANTERN_USER");
        return data;
    }
}
