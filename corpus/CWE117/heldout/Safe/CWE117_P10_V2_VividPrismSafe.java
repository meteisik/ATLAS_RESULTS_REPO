import java.util.logging.Logger;

public class CWE117_P10_V2_VividPrismSafe {

    public static String data;

    public void handleVividPrism() {
        if (true) {
            data = System.getenv("VIVID_PRISM_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_VividPrismSafeSink()).logVividPrism();
    }
}

class CWE117_P10_V2_VividPrismSafeSink {
    public void logVividPrism() {
        String data = CWE117_P10_V2_VividPrismSafe.data;
        Logger vividPrismLogger = Logger.getLogger("vividPrism.audit");
        vividPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
