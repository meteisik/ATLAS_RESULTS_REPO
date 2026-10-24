import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrFlareSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    static class Container {
        public String containerOne;
    }

    public void handleZephyrFlare() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_FLARE_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_ZephyrFlareSafeSink()).logZephyrFlare(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrFlareSafeSink {
    public void logZephyrFlare(CWE117_P09_V2_ZephyrFlareSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrFlareLogger = Logger.getLogger("zephyrFlare.audit");
        zephyrFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
