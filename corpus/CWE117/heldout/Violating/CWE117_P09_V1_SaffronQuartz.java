import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronQuartz {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronQuartz() {
        String data;
        data = System.getenv("SAFFRON_QUARTZ_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronQuartzSink()).logSaffronQuartz(dataContainer);
    }
}

class CWE117_P09_V1_SaffronQuartzSink {
    public void logSaffronQuartz(CWE117_P09_V1_SaffronQuartz.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronQuartzLogger = Logger.getLogger("saffronQuartz.audit");
        saffronQuartzLogger.info("Login attempt for user " + data);
    }
}
