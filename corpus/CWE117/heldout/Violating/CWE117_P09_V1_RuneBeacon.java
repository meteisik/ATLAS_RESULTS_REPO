import java.util.logging.Logger;

public class CWE117_P09_V1_RuneBeacon {

    static class Container {
        public String containerOne;
    }

    public void handleRuneBeacon() {
        String data;
        data = System.getenv("RUNE_BEACON_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_RuneBeaconSink()).logRuneBeacon(dataContainer);
    }
}

class CWE117_P09_V1_RuneBeaconSink {
    public void logRuneBeacon(CWE117_P09_V1_RuneBeacon.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger runeBeaconLogger = Logger.getLogger("runeBeacon.audit");
        runeBeaconLogger.info("Login attempt for user " + data);
    }
}
