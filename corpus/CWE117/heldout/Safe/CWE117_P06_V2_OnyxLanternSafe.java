import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxLanternSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleOnyxLantern() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ONYX_LANTERN_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxLanternSafeSink()).logOnyxLantern(data);
    }
}

class CWE117_P06_V2_OnyxLanternSafeSink {
    public void logOnyxLantern(String data) {
        Logger onyxLanternLogger = Logger.getLogger("onyxLantern.audit");
        onyxLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
