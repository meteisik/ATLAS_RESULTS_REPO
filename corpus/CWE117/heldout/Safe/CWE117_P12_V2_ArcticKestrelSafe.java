import java.util.logging.Logger;

public class CWE117_P12_V2_ArcticKestrelSafe {

    public void handleArcticKestrel() {
        String data;
        if (true) {
            data = System.getenv("ARCTIC_KESTREL_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_ArcticKestrelSafeBase baseObject = new CWE117_P12_V2_ArcticKestrelSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_ArcticKestrelSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_ArcticKestrelSafeSink extends CWE117_P12_V2_ArcticKestrelSafeBase {
    public void action(String data) {
        Logger arcticKestrelLogger = Logger.getLogger("arcticKestrel.audit");
        arcticKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
