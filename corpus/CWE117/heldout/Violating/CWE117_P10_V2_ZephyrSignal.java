import java.util.logging.Logger;

public class CWE117_P10_V2_ZephyrSignal {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void handleZephyrSignal() {
        if (IO.staticFive == 5) {
            data = System.getenv("ZEPHYR_SIGNAL_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ZephyrSignalSink()).logZephyrSignal();
    }
}

class CWE117_P10_V2_ZephyrSignalSink {
    public void logZephyrSignal() {
        String data = CWE117_P10_V2_ZephyrSignal.data;
        Logger zephyrSignalLogger = Logger.getLogger("zephyrSignal.audit");
        zephyrSignalLogger.info("Login attempt for user " + data);
    }
}
