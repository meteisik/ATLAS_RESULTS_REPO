import java.util.logging.Logger;

public class CWE117_P09_V1_SilentLotus {

    static class Container {
        public String containerOne;
    }

    public void handleSilentLotus() {
        String data;
        data = System.getenv("SILENT_LOTUS_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SilentLotusSink()).logSilentLotus(dataContainer);
    }
}

class CWE117_P09_V1_SilentLotusSink {
    public void logSilentLotus(CWE117_P09_V1_SilentLotus.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger silentLotusLogger = Logger.getLogger("silentLotus.audit");
        silentLotusLogger.info("Login attempt for user " + data);
    }
}
