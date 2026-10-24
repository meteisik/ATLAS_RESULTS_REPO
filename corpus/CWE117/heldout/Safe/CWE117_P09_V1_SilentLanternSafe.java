import java.util.logging.Logger;

public class CWE117_P09_V1_SilentLanternSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSilentLantern() {
        String data;
        data = System.getenv("SILENT_LANTERN_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SilentLanternSafeSink()).logSilentLantern(dataContainer);
    }
}

class CWE117_P09_V1_SilentLanternSafeSink {
    public void logSilentLantern(CWE117_P09_V1_SilentLanternSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger silentLanternLogger = Logger.getLogger("silentLantern.audit");
        silentLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
