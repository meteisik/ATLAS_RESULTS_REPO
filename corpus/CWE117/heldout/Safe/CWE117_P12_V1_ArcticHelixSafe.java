import java.util.logging.Logger;

public class CWE117_P12_V1_ArcticHelixSafe {

    public void handleArcticHelix() {
        String data;
        data = System.getenv("ARCTIC_HELIX_USER");
        CWE117_P12_V1_ArcticHelixSafeBase baseObject = new CWE117_P12_V1_ArcticHelixSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ArcticHelixSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ArcticHelixSafeSink extends CWE117_P12_V1_ArcticHelixSafeBase {
    public void action(String data) {
        Logger arcticHelixLogger = Logger.getLogger("arcticHelix.audit");
        arcticHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
