import java.util.logging.Logger;

public class CWE117_P09_V2_AmberPrismSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    static class Container {
        public String containerOne;
    }

    public void handleAmberPrism() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AMBER_PRISM_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_AmberPrismSafeSink()).logAmberPrism(dataContainer);
    }
}

class CWE117_P09_V2_AmberPrismSafeSink {
    public void logAmberPrism(CWE117_P09_V2_AmberPrismSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger amberPrismLogger = Logger.getLogger("amberPrism.audit");
        amberPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
