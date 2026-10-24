import java.util.logging.Logger;

public class CWE117_P09_V1_SilentKestrelSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSilentKestrel() {
        String data;
        data = System.getenv("SILENT_KESTREL_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SilentKestrelSafeSink()).logSilentKestrel(dataContainer);
    }
}

class CWE117_P09_V1_SilentKestrelSafeSink {
    public void logSilentKestrel(CWE117_P09_V1_SilentKestrelSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger silentKestrelLogger = Logger.getLogger("silentKestrel.audit");
        silentKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
