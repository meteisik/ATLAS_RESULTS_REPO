import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryNebula {

    private String ivoryNebulaData;

    private void logIvoryNebula() {
        String data = ivoryNebulaData;
        Logger ivoryNebulaLogger = Logger.getLogger("ivoryNebula.audit");
        ivoryNebulaLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryNebula() {
        String data;
        data = System.getenv("IVORY_NEBULA_USER");
        ivoryNebulaData = data;
        logIvoryNebula();
    }
}
