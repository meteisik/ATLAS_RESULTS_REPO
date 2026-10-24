import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrMantis {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String containerOne;
    }

    public void handleZephyrMantis() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ZEPHYR_MANTIS_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_ZephyrMantisSink()).logZephyrMantis(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrMantisSink {
    public void logZephyrMantis(CWE117_P09_V2_ZephyrMantis.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrMantisLogger = Logger.getLogger("zephyrMantis.audit");
        zephyrMantisLogger.info("Login attempt for user " + data);
    }
}
