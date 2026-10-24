import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronPrismSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronPrism() {
        String data;
        data = System.getenv("SAFFRON_PRISM_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronPrismSafeSink()).logSaffronPrism(dataContainer);
    }
}

class CWE117_P09_V1_SaffronPrismSafeSink {
    public void logSaffronPrism(CWE117_P09_V1_SaffronPrismSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronPrismLogger = Logger.getLogger("saffronPrism.audit");
        saffronPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
