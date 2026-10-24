import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrSignal {
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

    public void handleZephyrSignal() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("ZEPHYR_SIGNAL_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_ZephyrSignalSink()).logZephyrSignal(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrSignalSink {
    public void logZephyrSignal(CWE117_P09_V2_ZephyrSignal.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrSignalLogger = Logger.getLogger("zephyrSignal.audit");
        zephyrSignalLogger.info("Login attempt for user " + data);
    }
}
