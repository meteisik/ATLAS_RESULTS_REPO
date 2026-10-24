import java.util.logging.Logger;

public class CWE117_P12_V2_CobaltLantern {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleCobaltLantern() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("COBALT_LANTERN_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CobaltLanternBase baseObject = new CWE117_P12_V2_CobaltLanternSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CobaltLanternBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CobaltLanternSink extends CWE117_P12_V2_CobaltLanternBase {
    public void action(String data) {
        Logger cobaltLanternLogger = Logger.getLogger("cobaltLantern.audit");
        cobaltLanternLogger.info("Login attempt for user " + data);
    }
}
