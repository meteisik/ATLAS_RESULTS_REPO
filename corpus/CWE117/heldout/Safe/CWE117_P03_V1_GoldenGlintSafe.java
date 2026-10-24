import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenGlintSafe {

    private void logGoldenGlint(String data) {
        Logger goldenGlintLogger = Logger.getLogger("goldenGlint.audit");
        goldenGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleGoldenGlint() {
        String data;
        data = System.getenv("GOLDEN_GLINT_USER");
        logGoldenGlint(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
