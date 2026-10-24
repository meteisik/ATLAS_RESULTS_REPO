import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrQuartz {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    static class Container {
        public String containerOne;
    }

    public void handleZephyrQuartz() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("ZEPHYR_QUARTZ_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_ZephyrQuartzSink()).logZephyrQuartz(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrQuartzSink {
    public void logZephyrQuartz(CWE117_P09_V2_ZephyrQuartz.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrQuartzLogger = Logger.getLogger("zephyrQuartz.audit");
        zephyrQuartzLogger.info("Login attempt for user " + data);
    }
}
