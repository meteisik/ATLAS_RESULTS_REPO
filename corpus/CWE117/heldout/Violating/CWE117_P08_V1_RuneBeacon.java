import java.util.logging.Logger;

public class CWE117_P08_V1_RuneBeacon {

    public void handleRuneBeacon() {
        String data;
        data = System.getenv("RUNE_BEACON_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_RuneBeaconSink()).logRuneBeacon(dataArray);
    }
}

class CWE117_P08_V1_RuneBeaconSink {
    public void logRuneBeacon(String[] dataArray) {
        String data = dataArray[2];
        Logger runeBeaconLogger = Logger.getLogger("runeBeacon.audit");
        runeBeaconLogger.info("Login attempt for user " + data);
    }
}
