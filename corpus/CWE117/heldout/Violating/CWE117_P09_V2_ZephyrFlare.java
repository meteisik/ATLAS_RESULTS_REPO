import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrFlare {
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
        (new CWE117_P09_V2_ZephyrFlareSink()).logZephyrFlare(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrFlareSink {
    public void logZephyrFlare(CWE117_P09_V2_ZephyrFlare.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrFlareLogger = Logger.getLogger("zephyrFlare.audit");
        zephyrFlareLogger.info("Login attempt for user " + data);
    }
}
