import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrPrismSafe {
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

    public void handleZephyrPrism() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ZEPHYR_PRISM_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_ZephyrPrismSafeSink()).logZephyrPrism(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrPrismSafeSink {
    public void logZephyrPrism(CWE117_P09_V2_ZephyrPrismSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrPrismLogger = Logger.getLogger("zephyrPrism.audit");
        zephyrPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
