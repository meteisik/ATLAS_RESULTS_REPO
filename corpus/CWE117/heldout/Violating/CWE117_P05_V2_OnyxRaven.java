import java.util.logging.Logger;

public class CWE117_P05_V2_OnyxRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String onyxRavenData;

    private void logOnyxRaven() {
        String data = onyxRavenData;
        Logger onyxRavenLogger = Logger.getLogger("onyxRaven.audit");
        onyxRavenLogger.info("Login attempt for user " + data);
    }

    public void handleOnyxRaven() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("ONYX_RAVEN_USER");
        } else {
            data = null;
        }
        onyxRavenData = data;
        logOnyxRaven();
    }
}
