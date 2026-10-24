import java.util.logging.Logger;

public class CWE117_P01_V1_CrimsonHarborSafe {

    public void handleCrimsonHarbor() {
        String data;
        data = System.getenv("CRIMSON_HARBOR_USER");
        Logger crimsonHarborLogger = Logger.getLogger("crimsonHarbor.audit");
        crimsonHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
