import java.util.logging.Logger;

public class CWE117_P12_V2_CobaltLanternSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleCobaltLantern() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("COBALT_LANTERN_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CobaltLanternSafeBase baseObject = new CWE117_P12_V2_CobaltLanternSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CobaltLanternSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CobaltLanternSafeSink extends CWE117_P12_V2_CobaltLanternSafeBase {
    public void action(String data) {
        Logger cobaltLanternLogger = Logger.getLogger("cobaltLantern.audit");
        cobaltLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
