import java.util.logging.Logger;

public class CWE117_P01_V2_IvoryLanternSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleIvoryLantern() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("IVORY_LANTERN_USER");
        } else {
            data = null;
        }
        Logger ivoryLanternLogger = Logger.getLogger("ivoryLantern.audit");
        ivoryLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
