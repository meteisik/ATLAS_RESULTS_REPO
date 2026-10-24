import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianNebula {

    public void handleObsidianNebula() {
        String data;
        data = (new CWE117_P07_V1_ObsidianNebulaSource()).readObsidianNebula();
        Logger obsidianNebulaLogger = Logger.getLogger("obsidianNebula.audit");
        obsidianNebulaLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_ObsidianNebulaSource {
    public String readObsidianNebula() {
        String data;
        data = System.getenv("OBSIDIAN_NEBULA_USER");
        return data;
    }
}
