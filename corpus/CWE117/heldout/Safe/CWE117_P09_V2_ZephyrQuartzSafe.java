import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrQuartzSafe {
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
        (new CWE117_P09_V2_ZephyrQuartzSafeSink()).logZephyrQuartz(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrQuartzSafeSink {
    public void logZephyrQuartz(CWE117_P09_V2_ZephyrQuartzSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrQuartzLogger = Logger.getLogger("zephyrQuartz.audit");
        zephyrQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
