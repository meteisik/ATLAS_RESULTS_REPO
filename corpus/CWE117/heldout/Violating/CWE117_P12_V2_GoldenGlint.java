import java.util.logging.Logger;

public class CWE117_P12_V2_GoldenGlint {
    private static int privateFive = 5;

    public void handleGoldenGlint() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("GOLDEN_GLINT_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_GoldenGlintBase baseObject = new CWE117_P12_V2_GoldenGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_GoldenGlintBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_GoldenGlintSink extends CWE117_P12_V2_GoldenGlintBase {
    public void action(String data) {
        Logger goldenGlintLogger = Logger.getLogger("goldenGlint.audit");
        goldenGlintLogger.info("Login attempt for user " + data);
    }
}
