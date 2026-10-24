import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryHarborSafe {

    private void logIvoryHarbor(String data) {
        Logger ivoryHarborLogger = Logger.getLogger("ivoryHarbor.audit");
        ivoryHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleIvoryHarbor() {
        String data;
        data = System.getenv("IVORY_HARBOR_USER");
        logIvoryHarbor(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
