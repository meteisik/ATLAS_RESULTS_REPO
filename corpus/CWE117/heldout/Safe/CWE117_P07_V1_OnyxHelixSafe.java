import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxHelixSafe {

    public void handleOnyxHelix() {
        String data;
        data = (new CWE117_P07_V1_OnyxHelixSafeSource()).readOnyxHelix();
        Logger onyxHelixLogger = Logger.getLogger("onyxHelix.audit");
        onyxHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_OnyxHelixSafeSource {
    public String readOnyxHelix() {
        String data;
        data = System.getenv("ONYX_HELIX_USER");
        return data;
    }
}
