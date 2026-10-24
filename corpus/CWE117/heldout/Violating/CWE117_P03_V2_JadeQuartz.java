import java.util.logging.Logger;

public class CWE117_P03_V2_JadeQuartz {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void logJadeQuartz(String data) {
        Logger jadeQuartzLogger = Logger.getLogger("jadeQuartz.audit");
        jadeQuartzLogger.info("Login attempt for user " + data);
    }

    public void handleJadeQuartz() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("JADE_QUARTZ_USER");
        } else {
            data = null;
        }
        logJadeQuartz(data);
    }
}
