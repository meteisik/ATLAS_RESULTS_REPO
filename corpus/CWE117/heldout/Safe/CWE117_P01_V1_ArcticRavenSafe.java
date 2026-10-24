import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticRavenSafe {

    public void handleArcticRaven() {
        String data;
        data = System.getenv("ARCTIC_RAVEN_USER");
        Logger arcticRavenLogger = Logger.getLogger("arcticRaven.audit");
        arcticRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
