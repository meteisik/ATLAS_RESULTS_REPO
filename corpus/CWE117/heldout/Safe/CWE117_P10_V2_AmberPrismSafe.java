import java.util.logging.Logger;

public class CWE117_P10_V2_AmberPrismSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public static String data;

    public void handleAmberPrism() {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AMBER_PRISM_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AmberPrismSafeSink()).logAmberPrism();
    }
}

class CWE117_P10_V2_AmberPrismSafeSink {
    public void logAmberPrism() {
        String data = CWE117_P10_V2_AmberPrismSafe.data;
        Logger amberPrismLogger = Logger.getLogger("amberPrism.audit");
        amberPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
