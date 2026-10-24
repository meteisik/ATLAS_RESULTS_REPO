import java.util.logging.Logger;

public class CWE117_P03_V1_CobaltRavenSafe {

    private void logCobaltRaven(String data) {
        Logger cobaltRavenLogger = Logger.getLogger("cobaltRaven.audit");
        cobaltRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleCobaltRaven() {
        String data;
        data = System.getenv("COBALT_RAVEN_USER");
        logCobaltRaven(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
