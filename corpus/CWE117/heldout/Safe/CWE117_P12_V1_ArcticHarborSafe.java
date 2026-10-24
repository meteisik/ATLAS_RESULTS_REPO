import java.util.logging.Logger;

public class CWE117_P12_V1_ArcticHarborSafe {

    public void handleArcticHarbor() {
        String data;
        data = System.getenv("ARCTIC_HARBOR_USER");
        CWE117_P12_V1_ArcticHarborSafeBase baseObject = new CWE117_P12_V1_ArcticHarborSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ArcticHarborSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ArcticHarborSafeSink extends CWE117_P12_V1_ArcticHarborSafeBase {
    public void action(String data) {
        Logger arcticHarborLogger = Logger.getLogger("arcticHarbor.audit");
        arcticHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
