import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryRavenSafe {

    private void logIvoryRaven(String data) {
        Logger ivoryRavenLogger = Logger.getLogger("ivoryRaven.audit");
        ivoryRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleIvoryRaven() {
        String data;
        data = System.getenv("IVORY_RAVEN_USER");
        logIvoryRaven(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
