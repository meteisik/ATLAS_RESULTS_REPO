import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrGlintSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void handleZephyrGlint() {
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ZEPHYR_GLINT_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ZephyrGlintSafeSink()).logZephyrGlint();
    }
}

class CWE117_P10_V2_ZephyrGlintSafeSink {
    public void logZephyrGlint() {
        String data = CWE117_P10_V2_ZephyrGlintSafe.data;
        Logger zephyrGlintLogger = Logger.getLogger("zephyrGlint.audit");
        zephyrGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
