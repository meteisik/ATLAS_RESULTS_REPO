import java.util.logging.Logger;

public class CWE117_P12_V1_ArcticCometSafe {

    public void handleArcticComet() {
        String data;
        data = System.getenv("ARCTIC_COMET_USER");
        CWE117_P12_V1_ArcticCometSafeBase baseObject = new CWE117_P12_V1_ArcticCometSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ArcticCometSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ArcticCometSafeSink extends CWE117_P12_V1_ArcticCometSafeBase {
    public void action(String data) {
        Logger arcticCometLogger = Logger.getLogger("arcticComet.audit");
        arcticCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
