import java.util.logging.Logger;

public class CWE117_P12_V2_ArcticLotusSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleArcticLotus() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ARCTIC_LOTUS_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_ArcticLotusSafeBase baseObject = new CWE117_P12_V2_ArcticLotusSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_ArcticLotusSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_ArcticLotusSafeSink extends CWE117_P12_V2_ArcticLotusSafeBase {
    public void action(String data) {
        Logger arcticLotusLogger = Logger.getLogger("arcticLotus.audit");
        arcticLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
