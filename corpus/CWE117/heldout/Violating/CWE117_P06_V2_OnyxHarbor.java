import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxHarbor {
    private static boolean privateTrue = true;

    public void handleOnyxHarbor() {
        String data;
        if (privateTrue) {
            data = System.getenv("ONYX_HARBOR_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxHarborSink()).logOnyxHarbor(data);
    }
}

class CWE117_P06_V2_OnyxHarborSink {
    public void logOnyxHarbor(String data) {
        Logger onyxHarborLogger = Logger.getLogger("onyxHarbor.audit");
        onyxHarborLogger.info("Login attempt for user " + data);
    }
}
