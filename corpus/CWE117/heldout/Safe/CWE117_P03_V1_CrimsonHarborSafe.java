import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonHarborSafe {

    private void logCrimsonHarbor(String data) {
        Logger crimsonHarborLogger = Logger.getLogger("crimsonHarbor.audit");
        crimsonHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleCrimsonHarbor() {
        String data;
        data = System.getenv("CRIMSON_HARBOR_USER");
        logCrimsonHarbor(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
