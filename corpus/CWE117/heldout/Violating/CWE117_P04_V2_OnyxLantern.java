import java.util.logging.Logger;

public class CWE117_P04_V2_OnyxLantern {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String readOnyxLantern() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_LANTERN_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleOnyxLantern() {
        String data = readOnyxLantern();
        Logger onyxLanternLogger = Logger.getLogger("onyxLantern.audit");
        onyxLanternLogger.info("Login attempt for user " + data);
    }
}
