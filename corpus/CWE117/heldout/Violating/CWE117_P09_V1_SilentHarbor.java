import java.util.logging.Logger;

public class CWE117_P09_V1_SilentHarbor {

    static class Container {
        public String containerOne;
    }

    public void handleSilentHarbor() {
        String data;
        data = System.getenv("SILENT_HARBOR_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SilentHarborSink()).logSilentHarbor(dataContainer);
    }
}

class CWE117_P09_V1_SilentHarborSink {
    public void logSilentHarbor(CWE117_P09_V1_SilentHarbor.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger silentHarborLogger = Logger.getLogger("silentHarbor.audit");
        silentHarborLogger.info("Login attempt for user " + data);
    }
}
