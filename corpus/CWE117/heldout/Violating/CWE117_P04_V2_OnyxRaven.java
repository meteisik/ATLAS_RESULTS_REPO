import java.util.logging.Logger;

public class CWE117_P04_V2_OnyxRaven {
    private static boolean privateReturnsTrue() { return true; }

    private String readOnyxRaven() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ONYX_RAVEN_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleOnyxRaven() {
        String data = readOnyxRaven();
        Logger onyxRavenLogger = Logger.getLogger("onyxRaven.audit");
        onyxRavenLogger.info("Login attempt for user " + data);
    }
}
