import java.util.logging.Logger;

public class CWE117_P09_V2_VividSignal {

    static class Container {
        public String containerOne;
    }

    public void handleVividSignal() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("VIVID_SIGNAL_USER");
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VividSignalSink()).logVividSignal(dataContainer);
    }
}

class CWE117_P09_V2_VividSignalSink {
    public void logVividSignal(CWE117_P09_V2_VividSignal.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger vividSignalLogger = Logger.getLogger("vividSignal.audit");
        vividSignalLogger.info("Login attempt for user " + data);
    }
}
