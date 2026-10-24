import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryLanternSafe {

    private void logIvoryLantern(String data) {
        Logger ivoryLanternLogger = Logger.getLogger("ivoryLantern.audit");
        ivoryLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleIvoryLantern() {
        String data;
        data = System.getenv("IVORY_LANTERN_USER");
        logIvoryLantern(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
