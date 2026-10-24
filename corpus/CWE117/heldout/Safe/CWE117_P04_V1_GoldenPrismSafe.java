import java.util.logging.Logger;

public class CWE117_P04_V1_GoldenPrismSafe {

    private String readGoldenPrism() {
        String data;
        data = System.getenv("GOLDEN_PRISM_USER");
        return data;
    }

    public void handleGoldenPrism() {
        String data = readGoldenPrism();
        Logger goldenPrismLogger = Logger.getLogger("goldenPrism.audit");
        goldenPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
