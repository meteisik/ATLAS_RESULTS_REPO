import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxHelixSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleOnyxHelix() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ONYX_HELIX_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxHelixSafeSink()).logOnyxHelix(data);
    }
}

class CWE117_P06_V2_OnyxHelixSafeSink {
    public void logOnyxHelix(String data) {
        Logger onyxHelixLogger = Logger.getLogger("onyxHelix.audit");
        onyxHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
