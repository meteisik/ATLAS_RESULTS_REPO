import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxHarborSafe {

    public void handleOnyxHarbor() {
        String data;
        data = (new CWE117_P07_V1_OnyxHarborSafeSource()).readOnyxHarbor();
        Logger onyxHarborLogger = Logger.getLogger("onyxHarbor.audit");
        onyxHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_OnyxHarborSafeSource {
    public String readOnyxHarbor() {
        String data;
        data = System.getenv("ONYX_HARBOR_USER");
        return data;
    }
}
