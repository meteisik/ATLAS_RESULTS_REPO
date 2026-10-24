import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrQuartz {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void handleZephyrQuartz() {
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_QUARTZ_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ZephyrQuartzSink()).logZephyrQuartz();
    }
}

class CWE117_P10_V2_ZephyrQuartzSink {
    public void logZephyrQuartz() {
        String data = CWE117_P10_V2_ZephyrQuartz.data;
        Logger zephyrQuartzLogger = Logger.getLogger("zephyrQuartz.audit");
        zephyrQuartzLogger.info("Login attempt for user " + data);
    }
}
