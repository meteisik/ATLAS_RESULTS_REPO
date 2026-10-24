import java.util.logging.Logger;

public class CWE117_P12_V2_CobaltRavenSafe {
    private static int privateFive = 5;

    public void handleCobaltRaven() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("COBALT_RAVEN_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CobaltRavenSafeBase baseObject = new CWE117_P12_V2_CobaltRavenSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CobaltRavenSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CobaltRavenSafeSink extends CWE117_P12_V2_CobaltRavenSafeBase {
    public void action(String data) {
        Logger cobaltRavenLogger = Logger.getLogger("cobaltRaven.audit");
        cobaltRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
