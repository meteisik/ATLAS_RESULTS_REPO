import java.util.logging.Logger;

public class CWE117_P05_V1_IvoryLanternSafe {

    private String ivoryLanternData;

    private void logIvoryLantern() {
        String data = ivoryLanternData;
        Logger ivoryLanternLogger = Logger.getLogger("ivoryLantern.audit");
        ivoryLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleIvoryLantern() {
        String data;
        data = System.getenv("IVORY_LANTERN_USER");
        ivoryLanternData = data;
        logIvoryLantern();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
