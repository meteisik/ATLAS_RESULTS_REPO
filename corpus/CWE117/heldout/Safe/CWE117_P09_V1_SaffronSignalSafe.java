import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronSignalSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronSignal() {
        String data;
        data = System.getenv("SAFFRON_SIGNAL_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronSignalSafeSink()).logSaffronSignal(dataContainer);
    }
}

class CWE117_P09_V1_SaffronSignalSafeSink {
    public void logSaffronSignal(CWE117_P09_V1_SaffronSignalSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronSignalLogger = Logger.getLogger("saffronSignal.audit");
        saffronSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
