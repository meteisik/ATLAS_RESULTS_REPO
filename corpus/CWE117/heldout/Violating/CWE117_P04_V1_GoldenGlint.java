import java.util.logging.Logger;

public class CWE117_P04_V1_GoldenGlint {

    private String readGoldenGlint() {
        String data;
        data = System.getenv("GOLDEN_GLINT_USER");
        return data;
    }

    public void handleGoldenGlint() {
        String data = readGoldenGlint();
        Logger goldenGlintLogger = Logger.getLogger("goldenGlint.audit");
        goldenGlintLogger.info("Login attempt for user " + data);
    }
}
