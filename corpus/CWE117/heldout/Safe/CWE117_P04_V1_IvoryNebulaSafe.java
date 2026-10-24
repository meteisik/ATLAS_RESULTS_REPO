import java.util.logging.Logger;

public class CWE117_P04_V1_IvoryNebulaSafe {

    private String readIvoryNebula() {
        String data;
        data = System.getenv("IVORY_NEBULA_USER");
        return data;
    }

    public void handleIvoryNebula() {
        String data = readIvoryNebula();
        Logger ivoryNebulaLogger = Logger.getLogger("ivoryNebula.audit");
        ivoryNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
