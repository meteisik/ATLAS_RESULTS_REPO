import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianNebulaSafe {

    public void handleObsidianNebula() {
        String data;
        data = (new CWE117_P07_V1_ObsidianNebulaSafeSource()).readObsidianNebula();
        Logger obsidianNebulaLogger = Logger.getLogger("obsidianNebula.audit");
        obsidianNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_ObsidianNebulaSafeSource {
    public String readObsidianNebula() {
        String data;
        data = System.getenv("OBSIDIAN_NEBULA_USER");
        return data;
    }
}
