import java.util.logging.Logger;

public class CWE117_P09_V2_ZephyrGlintSafe {
    private static int privateFive = 5;

    static class Container {
        public String containerOne;
    }

    public void handleZephyrGlint() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ZEPHYR_GLINT_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_ZephyrGlintSafeSink()).logZephyrGlint(dataContainer);
    }
}

class CWE117_P09_V2_ZephyrGlintSafeSink {
    public void logZephyrGlint(CWE117_P09_V2_ZephyrGlintSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger zephyrGlintLogger = Logger.getLogger("zephyrGlint.audit");
        zephyrGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
