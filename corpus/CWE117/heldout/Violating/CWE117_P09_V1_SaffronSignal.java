import java.util.logging.Logger;

public class CWE117_P09_V1_SaffronSignal {

    static class Container {
        public String containerOne;
    }

    public void handleSaffronSignal() {
        String data;
        data = System.getenv("SAFFRON_SIGNAL_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SaffronSignalSink()).logSaffronSignal(dataContainer);
    }
}

class CWE117_P09_V1_SaffronSignalSink {
    public void logSaffronSignal(CWE117_P09_V1_SaffronSignal.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger saffronSignalLogger = Logger.getLogger("saffronSignal.audit");
        saffronSignalLogger.info("Login attempt for user " + data);
    }
}
