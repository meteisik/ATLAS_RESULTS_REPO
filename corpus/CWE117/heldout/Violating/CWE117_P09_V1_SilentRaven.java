import java.util.logging.Logger;

public class CWE117_P09_V1_SilentRaven {

    static class Container {
        public String containerOne;
    }

    public void handleSilentRaven() {
        String data;
        data = System.getenv("SILENT_RAVEN_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SilentRavenSink()).logSilentRaven(dataContainer);
    }
}

class CWE117_P09_V1_SilentRavenSink {
    public void logSilentRaven(CWE117_P09_V1_SilentRaven.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger silentRavenLogger = Logger.getLogger("silentRaven.audit");
        silentRavenLogger.info("Login attempt for user " + data);
    }
}
