import java.util.logging.Logger;

public class CWE117_P03_V2_LunarCometSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void logLunarComet(String data) {
        Logger lunarCometLogger = Logger.getLogger("lunarComet.audit");
        lunarCometLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleLunarComet() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("LUNAR_COMET_USER");
        } else {
            data = null;
        }
        logLunarComet(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
