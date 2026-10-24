import java.util.logging.Logger;

public class CWE117_P01_V2_GoldenPrismSafe {

    public void handleGoldenPrism() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("GOLDEN_PRISM_USER");
            break;
        default:
            data = null;
            break;
        }
        Logger goldenPrismLogger = Logger.getLogger("goldenPrism.audit");
        goldenPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
