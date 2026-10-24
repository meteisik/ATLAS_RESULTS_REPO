import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticHarborSafe {

    public void handleArcticHarbor() {
        String data;
        data = System.getenv("ARCTIC_HARBOR_USER");
        Logger arcticHarborLogger = Logger.getLogger("arcticHarbor.audit");
        arcticHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
