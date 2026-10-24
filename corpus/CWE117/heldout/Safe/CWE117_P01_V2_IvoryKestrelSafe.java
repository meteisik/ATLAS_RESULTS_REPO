import java.util.logging.Logger;

public class CWE117_P01_V2_IvoryKestrelSafe {
    private static int privateFive = 5;

    public void handleIvoryKestrel() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("IVORY_KESTREL_USER");
        } else {
            data = null;
        }
        Logger ivoryKestrelLogger = Logger.getLogger("ivoryKestrel.audit");
        ivoryKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
