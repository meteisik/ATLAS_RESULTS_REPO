import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonRavenSafe {

    public void handleCrimsonRaven() {
        String data;
        if (true) {
            data = System.getenv("CRIMSON_RAVEN_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CrimsonRavenSafeBase baseObject = new CWE117_P12_V2_CrimsonRavenSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonRavenSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonRavenSafeSink extends CWE117_P12_V2_CrimsonRavenSafeBase {
    public void action(String data) {
        Logger crimsonRavenLogger = Logger.getLogger("crimsonRaven.audit");
        crimsonRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
