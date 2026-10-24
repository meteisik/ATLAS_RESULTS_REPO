import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxHarborSafe {
    private static boolean privateTrue = true;

    public void handleOnyxHarbor() {
        String data;
        if (privateTrue) {
            data = System.getenv("ONYX_HARBOR_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxHarborSafeSink()).logOnyxHarbor(data);
    }
}

class CWE117_P06_V2_OnyxHarborSafeSink {
    public void logOnyxHarbor(String data) {
        Logger onyxHarborLogger = Logger.getLogger("onyxHarbor.audit");
        onyxHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
