import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxRavenSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleOnyxRaven() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ONYX_RAVEN_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxRavenSafeSink()).logOnyxRaven(data);
    }
}

class CWE117_P06_V2_OnyxRavenSafeSink {
    public void logOnyxRaven(String data) {
        Logger onyxRavenLogger = Logger.getLogger("onyxRaven.audit");
        onyxRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
