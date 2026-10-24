import java.util.logging.Logger;

public class CWE117_P04_V2_OnyxHarborSafe {

    private String readOnyxHarbor() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ONYX_HARBOR_USER");
        }
        return data;
    }

    public void handleOnyxHarbor() {
        String data = readOnyxHarbor();
        Logger onyxHarborLogger = Logger.getLogger("onyxHarbor.audit");
        onyxHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
