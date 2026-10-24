import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronAuroraSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronAurora() {
        String data;
        data = System.getenv("SAFFRON_AURORA_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronAuroraSafeSink()).logSaffronAurora(dataContainer);
    }
}

class CWE117_P09_V1_SaffronAuroraSafeSink {
    public void logSaffronAurora(CWE117_P09_V1_SaffronAuroraSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronAuroraLogger = Logger.getLogger("saffronAurora.audit");
        saffronAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
