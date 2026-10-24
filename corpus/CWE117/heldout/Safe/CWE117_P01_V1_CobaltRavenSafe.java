import java.util.logging.Logger;

public class CWE117_P01_V1_CobaltRavenSafe {

    public void handleCobaltRaven() {
        String data;
        data = System.getenv("COBALT_RAVEN_USER");
        Logger cobaltRavenLogger = Logger.getLogger("cobaltRaven.audit");
        cobaltRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
