import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenGlint {

    private void logGoldenGlint(String data) {
        Logger goldenGlintLogger = Logger.getLogger("goldenGlint.audit");
        goldenGlintLogger.info("Login attempt for user " + data);
    }

    public void handleGoldenGlint() {
        String data;
        data = System.getenv("GOLDEN_GLINT_USER");
        logGoldenGlint(data);
    }
}
