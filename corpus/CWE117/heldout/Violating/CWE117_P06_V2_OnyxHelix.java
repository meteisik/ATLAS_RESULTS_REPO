import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxHelix {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleOnyxHelix() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ONYX_HELIX_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxHelixSink()).logOnyxHelix(data);
    }
}

class CWE117_P06_V2_OnyxHelixSink {
    public void logOnyxHelix(String data) {
        Logger onyxHelixLogger = Logger.getLogger("onyxHelix.audit");
        onyxHelixLogger.info("Login attempt for user " + data);
    }
}
