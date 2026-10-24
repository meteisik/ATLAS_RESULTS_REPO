import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrAurora {

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
        (new CWE117_P09_V2_ZephyrAuroraSink()).logZephyrAurora(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrAuroraSink {
    public void logZephyrAurora(CWE117_P09_V2_ZephyrAurora.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrAuroraLogger = Logger.getLogger("zephyrAurora.audit");
        zephyrAuroraLogger.info("Login attempt for user " + data);
    }
}
