import java.util.logging.Logger;

public class CWE117_P09_V2_VividSignalSafe {

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
        (new CWE117_P09_V2_VividSignalSafeSink()).logVividSignal(dataContainer);
    }
}

class CWE117_P09_V2_VividSignalSafeSink {
    public void logVividSignal(CWE117_P09_V2_VividSignalSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger vividSignalLogger = Logger.getLogger("vividSignal.audit");
        vividSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
