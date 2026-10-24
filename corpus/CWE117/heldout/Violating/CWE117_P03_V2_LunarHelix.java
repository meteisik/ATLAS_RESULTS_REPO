import java.util.logging.Logger;

public class CWE117_P03_V2_LunarHelix {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void logLunarHelix(String data) {
        Logger lunarHelixLogger = Logger.getLogger("lunarHelix.audit");
        lunarHelixLogger.info("Login attempt for user " + data);
    }

    public void handleLunarHelix() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("LUNAR_HELIX_USER");
        } else {
            data = null;
        }
        logLunarHelix(data);
    }
}
