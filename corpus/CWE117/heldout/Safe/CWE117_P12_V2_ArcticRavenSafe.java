import java.util.logging.Logger;

public class CWE117_P12_V2_ArcticRavenSafe {
    private static int privateFive = 5;

    public void handleArcticRaven() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ARCTIC_RAVEN_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_ArcticRavenSafeBase baseObject = new CWE117_P12_V2_ArcticRavenSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_ArcticRavenSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_ArcticRavenSafeSink extends CWE117_P12_V2_ArcticRavenSafeBase {
    public void action(String data) {
        Logger arcticRavenLogger = Logger.getLogger("arcticRaven.audit");
        arcticRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
