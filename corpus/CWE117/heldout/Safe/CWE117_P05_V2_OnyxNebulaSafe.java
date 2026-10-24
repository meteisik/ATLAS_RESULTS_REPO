import java.util.logging.Logger;

public class CWE117_P05_V2_OnyxNebulaSafe {
    private static boolean privateReturnsTrue() { return true; }

    private String onyxNebulaData;

    private void logOnyxNebula() {
        String data = onyxNebulaData;
        Logger onyxNebulaLogger = Logger.getLogger("onyxNebula.audit");
        onyxNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleOnyxNebula() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ONYX_NEBULA_USER");
        } else {
            data = null;
        }
        onyxNebulaData = data;
        logOnyxNebula();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
