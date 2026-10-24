import java.util.logging.Logger;

public class CWE117_P09_V1_RuneBeaconSafe {

    static class Container {
        public String containerOne;
    }

    public void handleRuneBeacon() {
        String data;
        data = System.getenv("RUNE_BEACON_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_RuneBeaconSafeSink()).logRuneBeacon(dataContainer);
    }
}

class CWE117_P09_V1_RuneBeaconSafeSink {
    public void logRuneBeacon(CWE117_P09_V1_RuneBeaconSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger runeBeaconLogger = Logger.getLogger("runeBeacon.audit");
        runeBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
