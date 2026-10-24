import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryRavenSafe {

    private String ivoryRavenData;

    private void logIvoryRaven() {
        String data = ivoryRavenData;
        Logger ivoryRavenLogger = Logger.getLogger("ivoryRaven.audit");
        ivoryRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleIvoryRaven() {
        String data;
        data = System.getenv("IVORY_RAVEN_USER");
        ivoryRavenData = data;
        logIvoryRaven();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
