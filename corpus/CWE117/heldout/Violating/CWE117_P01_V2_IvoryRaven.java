import java.util.logging.Logger;

public class CWE117_P01_V2_IvoryRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleIvoryRaven() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("IVORY_RAVEN_USER");
        } else {
            data = null;
        }
        Logger ivoryRavenLogger = Logger.getLogger("ivoryRaven.audit");
        ivoryRavenLogger.info("Login attempt for user " + data);
    }
}
