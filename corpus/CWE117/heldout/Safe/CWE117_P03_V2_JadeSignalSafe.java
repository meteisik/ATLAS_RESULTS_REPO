import java.util.logging.Logger;

public class CWE117_P03_V2_JadeSignalSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void logJadeSignal(String data) {
        Logger jadeSignalLogger = Logger.getLogger("jadeSignal.audit");
        jadeSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleJadeSignal() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("JADE_SIGNAL_USER");
        } else {
            data = null;
        }
        logJadeSignal(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
