import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticRavenSafe {

    public static String data;

    public void handleArcticRaven() {
        if (5 == 5) {
            data = System.getenv("ARCTIC_RAVEN_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ArcticRavenSafeSink()).logArcticRaven();
    }
}

class CWE117_P10_V2_ArcticRavenSafeSink {
    public void logArcticRaven() {
        String data = CWE117_P10_V2_ArcticRavenSafe.data;
        Logger arcticRavenLogger = Logger.getLogger("arcticRaven.audit");
        arcticRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
