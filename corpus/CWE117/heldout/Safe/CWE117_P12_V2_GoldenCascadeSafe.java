import java.util.logging.Logger;

public class CWE117_P12_V2_GoldenCascadeSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleGoldenCascade() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("GOLDEN_CASCADE_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_GoldenCascadeSafeBase baseObject = new CWE117_P12_V2_GoldenCascadeSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_GoldenCascadeSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_GoldenCascadeSafeSink extends CWE117_P12_V2_GoldenCascadeSafeBase {
    public void action(String data) {
        Logger goldenCascadeLogger = Logger.getLogger("goldenCascade.audit");
        goldenCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
