import java.util.logging.Logger;

public class CWE117_P01_V2_GoldenAuroraSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleGoldenAurora() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("GOLDEN_AURORA_USER");
        } else {
            data = null;
        }
        Logger goldenAuroraLogger = Logger.getLogger("goldenAurora.audit");
        goldenAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
