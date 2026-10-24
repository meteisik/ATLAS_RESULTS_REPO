import java.util.logging.Logger;

public class CWE117_P12_V2_GoldenGlintSafe {
    private static int privateFive = 5;

    public void handleGoldenGlint() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("GOLDEN_GLINT_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_GoldenGlintSafeBase baseObject = new CWE117_P12_V2_GoldenGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_GoldenGlintSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_GoldenGlintSafeSink extends CWE117_P12_V2_GoldenGlintSafeBase {
    public void action(String data) {
        Logger goldenGlintLogger = Logger.getLogger("goldenGlint.audit");
        goldenGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
