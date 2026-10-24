import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenCascadeSafe {

    private void logGoldenCascade(String data) {
        Logger goldenCascadeLogger = Logger.getLogger("goldenCascade.audit");
        goldenCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleGoldenCascade() {
        String data;
        data = System.getenv("GOLDEN_CASCADE_USER");
        logGoldenCascade(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
