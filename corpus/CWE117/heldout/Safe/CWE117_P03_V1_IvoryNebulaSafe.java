import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryNebulaSafe {

    private void logIvoryNebula(String data) {
        Logger ivoryNebulaLogger = Logger.getLogger("ivoryNebula.audit");
        ivoryNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleIvoryNebula() {
        String data;
        data = System.getenv("IVORY_NEBULA_USER");
        logIvoryNebula(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
