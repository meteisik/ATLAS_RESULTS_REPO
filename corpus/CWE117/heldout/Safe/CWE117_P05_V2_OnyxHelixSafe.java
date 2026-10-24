import java.util.logging.Logger;

public class CWE117_P05_V2_OnyxHelixSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String onyxHelixData;

    private void logOnyxHelix() {
        String data = onyxHelixData;
        Logger onyxHelixLogger = Logger.getLogger("onyxHelix.audit");
        onyxHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleOnyxHelix() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_HELIX_USER");
        } else {
            data = null;
        }
        onyxHelixData = data;
        logOnyxHelix();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
