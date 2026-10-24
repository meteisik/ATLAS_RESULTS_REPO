import java.util.logging.Logger;

public class CWE117_P09_V1_SilentRavenSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSilentRaven() {
        String data;
        data = System.getenv("SILENT_RAVEN_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SilentRavenSafeSink()).logSilentRaven(dataContainer);
    }
}

class CWE117_P09_V1_SilentRavenSafeSink {
    public void logSilentRaven(CWE117_P09_V1_SilentRavenSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger silentRavenLogger = Logger.getLogger("silentRaven.audit");
        silentRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
