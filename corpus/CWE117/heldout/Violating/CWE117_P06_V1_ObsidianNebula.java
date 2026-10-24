import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianNebula {

    public void handleObsidianNebula() {
        String data;
        data = System.getenv("OBSIDIAN_NEBULA_USER");
        (new CWE117_P06_V1_ObsidianNebulaSink()).logObsidianNebula(data);
    }
}

class CWE117_P06_V1_ObsidianNebulaSink {
    public void logObsidianNebula(String data) {
        Logger obsidianNebulaLogger = Logger.getLogger("obsidianNebula.audit");
        obsidianNebulaLogger.info("Login attempt for user " + data);
    }
}
