import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryHelixSafe {

    private void logIvoryHelix(String data) {
        Logger ivoryHelixLogger = Logger.getLogger("ivoryHelix.audit");
        ivoryHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleIvoryHelix() {
        String data;
        data = System.getenv("IVORY_HELIX_USER");
        logIvoryHelix(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
