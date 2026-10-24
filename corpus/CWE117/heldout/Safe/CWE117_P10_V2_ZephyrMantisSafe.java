import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void handleZephyrMantis() {
        if (IO.staticTrue) {
            data = System.getenv("ZEPHYR_MANTIS_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ZephyrMantisSafeSink()).logZephyrMantis();
    }
}

class CWE117_P10_V2_ZephyrMantisSafeSink {
    public void logZephyrMantis() {
        String data = CWE117_P10_V2_ZephyrMantisSafe.data;
        Logger zephyrMantisLogger = Logger.getLogger("zephyrMantis.audit");
        zephyrMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
