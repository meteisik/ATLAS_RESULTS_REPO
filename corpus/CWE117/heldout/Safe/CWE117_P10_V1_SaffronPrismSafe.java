import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronPrismSafe {

    public static String data;

    public void handleSaffronPrism() {
        data = System.getenv("SAFFRON_PRISM_USER");
        (new CWE117_P10_V1_SaffronPrismSafeSink()).logSaffronPrism();
    }
}

class CWE117_P10_V1_SaffronPrismSafeSink {
    public void logSaffronPrism() {
        String data = CWE117_P10_V1_SaffronPrismSafe.data;
        Logger saffronPrismLogger = Logger.getLogger("saffronPrism.audit");
        saffronPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
