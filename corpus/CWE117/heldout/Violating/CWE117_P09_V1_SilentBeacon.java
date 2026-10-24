import java.util.logging.Logger;

public class CWE117_P09_V1_SilentBeacon {

    static class Container {
        public String containerOne;
    }

    public void handleSilentBeacon() {
        String data;
        data = System.getenv("SILENT_BEACON_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SilentBeaconSink()).logSilentBeacon(dataContainer);
    }
}

class CWE117_P09_V1_SilentBeaconSink {
    public void logSilentBeacon(CWE117_P09_V1_SilentBeacon.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger silentBeaconLogger = Logger.getLogger("silentBeacon.audit");
        silentBeaconLogger.info("Login attempt for user " + data);
    }
}
