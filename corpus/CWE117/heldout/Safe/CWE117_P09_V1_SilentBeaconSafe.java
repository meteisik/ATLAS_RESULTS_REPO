import java.util.logging.Logger;

public class CWE117_P09_V1_SilentBeaconSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSilentBeacon() {
        String data;
        data = System.getenv("SILENT_BEACON_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SilentBeaconSafeSink()).logSilentBeacon(dataContainer);
    }
}

class CWE117_P09_V1_SilentBeaconSafeSink {
    public void logSilentBeacon(CWE117_P09_V1_SilentBeaconSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger silentBeaconLogger = Logger.getLogger("silentBeacon.audit");
        silentBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
