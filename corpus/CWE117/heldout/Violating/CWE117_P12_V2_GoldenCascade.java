import java.util.logging.Logger;

public class CWE117_P12_V2_GoldenCascade {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleGoldenCascade() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("GOLDEN_CASCADE_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_GoldenCascadeBase baseObject = new CWE117_P12_V2_GoldenCascadeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_GoldenCascadeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_GoldenCascadeSink extends CWE117_P12_V2_GoldenCascadeBase {
    public void action(String data) {
        Logger goldenCascadeLogger = Logger.getLogger("goldenCascade.audit");
        goldenCascadeLogger.info("Login attempt for user " + data);
    }
}
