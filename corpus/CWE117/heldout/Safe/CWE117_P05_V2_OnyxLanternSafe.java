import java.util.logging.Logger;

public class CWE117_P05_V2_OnyxLanternSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String onyxLanternData;

    private void logOnyxLantern() {
        String data = onyxLanternData;
        Logger onyxLanternLogger = Logger.getLogger("onyxLantern.audit");
        onyxLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleOnyxLantern() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ONYX_LANTERN_USER");
        } else {
            data = null;
        }
        onyxLanternData = data;
        logOnyxLantern();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
