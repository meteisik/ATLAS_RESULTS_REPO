import java.util.logging.Logger;

public class CWE117_P12_V2_ArcticLanternSafe {

    public void handleArcticLantern() {
        String data;
        if (5 == 5) {
            data = System.getenv("ARCTIC_LANTERN_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_ArcticLanternSafeBase baseObject = new CWE117_P12_V2_ArcticLanternSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_ArcticLanternSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_ArcticLanternSafeSink extends CWE117_P12_V2_ArcticLanternSafeBase {
    public void action(String data) {
        Logger arcticLanternLogger = Logger.getLogger("arcticLantern.audit");
        arcticLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
