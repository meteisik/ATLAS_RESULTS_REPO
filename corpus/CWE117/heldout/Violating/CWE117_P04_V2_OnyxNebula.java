import java.util.logging.Logger;

public class CWE117_P04_V2_OnyxNebula {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String readOnyxNebula() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ONYX_NEBULA_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleOnyxNebula() {
        String data = readOnyxNebula();
        Logger onyxNebulaLogger = Logger.getLogger("onyxNebula.audit");
        onyxNebulaLogger.info("Login attempt for user " + data);
    }
}
