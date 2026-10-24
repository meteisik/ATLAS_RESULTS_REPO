import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrPrism {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void handleZephyrPrism() {
        if (IO.staticReturnsTrue()) {
            data = System.getenv("ZEPHYR_PRISM_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ZephyrPrismSink()).logZephyrPrism();
    }
}

class CWE117_P10_V2_ZephyrPrismSink {
    public void logZephyrPrism() {
        String data = CWE117_P10_V2_ZephyrPrism.data;
        Logger zephyrPrismLogger = Logger.getLogger("zephyrPrism.audit");
        zephyrPrismLogger.info("Login attempt for user " + data);
    }
}
