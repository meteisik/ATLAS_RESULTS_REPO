import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrSundialSafe {
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

    public void handleZephyrSundial() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_SUNDIAL_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_ZephyrSundialSafeSink()).logZephyrSundial(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrSundialSafeSink {
    public void logZephyrSundial(CWE117_P09_V2_ZephyrSundialSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrSundialLogger = Logger.getLogger("zephyrSundial.audit");
        zephyrSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
