import java.util.logging.Logger;

public class CWE117_P05_V2_OnyxHarborSafe {

    private String onyxHarborData;

    private void logOnyxHarbor() {
        String data = onyxHarborData;
        Logger onyxHarborLogger = Logger.getLogger("onyxHarbor.audit");
        onyxHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleOnyxHarbor() {
        String data;
        if (5 == 5) {
            data = System.getenv("ONYX_HARBOR_USER");
        } else {
            data = null;
        }
        onyxHarborData = data;
        logOnyxHarbor();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
