import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrAuroraSafe {

    static class Container {
        public String containerOne;
    }

    public void handleZephyrAurora() {
        String data;
        if (5 == 5) {
            data = System.getenv("ZEPHYR_AURORA_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_ZephyrAuroraSafeSink()).logZephyrAurora(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrAuroraSafeSink {
    public void logZephyrAurora(CWE117_P09_V2_ZephyrAuroraSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrAuroraLogger = Logger.getLogger("zephyrAurora.audit");
        zephyrAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
