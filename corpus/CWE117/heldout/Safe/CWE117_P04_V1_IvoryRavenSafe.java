import java.util.logging.Logger;

public class CWE117_P04_V1_IvoryRavenSafe {

    private String readIvoryRaven() {
        String data;
        data = System.getenv("IVORY_RAVEN_USER");
        return data;
    }

    public void handleIvoryRaven() {
        String data = readIvoryRaven();
        Logger ivoryRavenLogger = Logger.getLogger("ivoryRaven.audit");
        ivoryRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
