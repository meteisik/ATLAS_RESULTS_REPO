import java.util.logging.Logger;

public class CWE117_P09_V1_SilentLantern {

    static class Container {
        public String containerOne;
    }

    public void handleSilentLantern() {
        String data;
        data = System.getenv("SILENT_LANTERN_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SilentLanternSink()).logSilentLantern(dataContainer);
    }
}

class CWE117_P09_V1_SilentLanternSink {
    public void logSilentLantern(CWE117_P09_V1_SilentLantern.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger silentLanternLogger = Logger.getLogger("silentLantern.audit");
        silentLanternLogger.info("Login attempt for user " + data);
    }
}
