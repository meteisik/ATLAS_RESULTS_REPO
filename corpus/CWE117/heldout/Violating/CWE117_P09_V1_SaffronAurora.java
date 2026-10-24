import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronAurora {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronAurora() {
        String data;
        data = System.getenv("SAFFRON_AURORA_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronAuroraSink()).logSaffronAurora(dataContainer);
    }
}

class CWE117_P09_V1_SaffronAuroraSink {
    public void logSaffronAurora(CWE117_P09_V1_SaffronAurora.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronAuroraLogger = Logger.getLogger("saffronAurora.audit");
        saffronAuroraLogger.info("Login attempt for user " + data);
    }
}
