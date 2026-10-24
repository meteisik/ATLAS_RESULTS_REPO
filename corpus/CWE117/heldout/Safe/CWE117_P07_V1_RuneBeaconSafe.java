import java.util.logging.Logger;

public class CWE117_P07_V1_RuneBeaconSafe {

    public void handleRuneBeacon() {
        String data;
        data = (new CWE117_P07_V1_RuneBeaconSafeSource()).readRuneBeacon();
        Logger runeBeaconLogger = Logger.getLogger("runeBeacon.audit");
        runeBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_RuneBeaconSafeSource {
    public String readRuneBeacon() {
        String data;
        data = System.getenv("RUNE_BEACON_USER");
        return data;
    }
}
