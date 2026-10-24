import java.util.logging.Logger;

public class CWE117_P09_V1_SilentHarborSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSilentHarbor() {
        String data;
        data = System.getenv("SILENT_HARBOR_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SilentHarborSafeSink()).logSilentHarbor(dataContainer);
    }
}

class CWE117_P09_V1_SilentHarborSafeSink {
    public void logSilentHarbor(CWE117_P09_V1_SilentHarborSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger silentHarborLogger = Logger.getLogger("silentHarbor.audit");
        silentHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
