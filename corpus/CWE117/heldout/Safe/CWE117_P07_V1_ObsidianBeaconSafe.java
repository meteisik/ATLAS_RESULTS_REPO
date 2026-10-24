import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianBeaconSafe {

    public void handleObsidianBeacon() {
        String data;
        data = (new CWE117_P07_V1_ObsidianBeaconSafeSource()).readObsidianBeacon();
        Logger obsidianBeaconLogger = Logger.getLogger("obsidianBeacon.audit");
        obsidianBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_ObsidianBeaconSafeSource {
    public String readObsidianBeacon() {
        String data;
        data = System.getenv("OBSIDIAN_BEACON_USER");
        return data;
    }
}
