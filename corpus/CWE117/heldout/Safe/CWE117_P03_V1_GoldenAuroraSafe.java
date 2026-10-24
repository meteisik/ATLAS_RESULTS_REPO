import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenAuroraSafe {

    private void logGoldenAurora(String data) {
        Logger goldenAuroraLogger = Logger.getLogger("goldenAurora.audit");
        goldenAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleGoldenAurora() {
        String data;
        data = System.getenv("GOLDEN_AURORA_USER");
        logGoldenAurora(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
