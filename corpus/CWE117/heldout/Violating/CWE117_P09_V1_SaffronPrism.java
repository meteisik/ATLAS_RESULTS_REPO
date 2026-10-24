import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronPrism {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronPrism() {
        String data;
        data = System.getenv("SAFFRON_PRISM_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronPrismSink()).logSaffronPrism(dataContainer);
    }
}

class CWE117_P09_V1_SaffronPrismSink {
    public void logSaffronPrism(CWE117_P09_V1_SaffronPrism.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronPrismLogger = Logger.getLogger("saffronPrism.audit");
        saffronPrismLogger.info("Login attempt for user " + data);
    }
}
