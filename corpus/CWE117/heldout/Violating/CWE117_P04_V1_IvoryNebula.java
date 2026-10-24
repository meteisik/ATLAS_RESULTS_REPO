import java.util.logging.Logger;

public class CWE117_P04_V1_IvoryNebula {

    private String readIvoryNebula() {
        String data;
        data = System.getenv("IVORY_NEBULA_USER");
        return data;
    }

    public void handleIvoryNebula() {
        String data = readIvoryNebula();
        Logger ivoryNebulaLogger = Logger.getLogger("ivoryNebula.audit");
        ivoryNebulaLogger.info("Login attempt for user " + data);
    }
}
