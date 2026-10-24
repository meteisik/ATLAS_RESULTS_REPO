import java.util.logging.Logger;

public class CWE117_P04_V1_IvoryHarborSafe {

    private String readIvoryHarbor() {
        String data;
        data = System.getenv("IVORY_HARBOR_USER");
        return data;
    }

    public void handleIvoryHarbor() {
        String data = readIvoryHarbor();
        Logger ivoryHarborLogger = Logger.getLogger("ivoryHarbor.audit");
        ivoryHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
