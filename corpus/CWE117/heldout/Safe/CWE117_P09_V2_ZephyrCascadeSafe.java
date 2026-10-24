import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrCascadeSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    static class Container {
        public String containerOne;
    }

    public void handleZephyrCascade() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ZEPHYR_CASCADE_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_ZephyrCascadeSafeSink()).logZephyrCascade(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrCascadeSafeSink {
    public void logZephyrCascade(CWE117_P09_V2_ZephyrCascadeSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrCascadeLogger = Logger.getLogger("zephyrCascade.audit");
        zephyrCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
