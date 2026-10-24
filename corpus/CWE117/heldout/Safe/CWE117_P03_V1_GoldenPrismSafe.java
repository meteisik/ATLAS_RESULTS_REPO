import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenPrismSafe {

    private void logGoldenPrism(String data) {
        Logger goldenPrismLogger = Logger.getLogger("goldenPrism.audit");
        goldenPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleGoldenPrism() {
        String data;
        data = System.getenv("GOLDEN_PRISM_USER");
        logGoldenPrism(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
