import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianNebulaSafe {

    public void handleObsidianNebula() {
        String data;
        data = System.getenv("OBSIDIAN_NEBULA_USER");
        (new CWE117_P06_V1_ObsidianNebulaSafeSink()).logObsidianNebula(data);
    }
}

class CWE117_P06_V1_ObsidianNebulaSafeSink {
    public void logObsidianNebula(String data) {
        Logger obsidianNebulaLogger = Logger.getLogger("obsidianNebula.audit");
        obsidianNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
