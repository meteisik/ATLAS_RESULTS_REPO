import java.util.logging.Logger;

public class CWE117_P07_V1_RuneBeacon {

    public void handleRuneBeacon() {
        String data;
        data = (new CWE117_P07_V1_RuneBeaconSource()).readRuneBeacon();
        Logger runeBeaconLogger = Logger.getLogger("runeBeacon.audit");
        runeBeaconLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_RuneBeaconSource {
    public String readRuneBeacon() {
        String data;
        data = System.getenv("RUNE_BEACON_USER");
        return data;
    }
}
