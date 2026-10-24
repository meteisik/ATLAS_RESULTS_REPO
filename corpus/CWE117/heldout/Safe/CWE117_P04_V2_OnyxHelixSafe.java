import java.util.logging.Logger;

public class CWE117_P04_V2_OnyxHelixSafe {

    private String readOnyxHelix() {
        String data;
        if (true) {
            data = System.getenv("ONYX_HELIX_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleOnyxHelix() {
        String data = readOnyxHelix();
        Logger onyxHelixLogger = Logger.getLogger("onyxHelix.audit");
        onyxHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
