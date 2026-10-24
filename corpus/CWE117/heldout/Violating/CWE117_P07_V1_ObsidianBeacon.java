import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianBeacon {

    public void handleObsidianBeacon() {
        String data;
        data = (new CWE117_P07_V1_ObsidianBeaconSource()).readObsidianBeacon();
        Logger obsidianBeaconLogger = Logger.getLogger("obsidianBeacon.audit");
        obsidianBeaconLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_ObsidianBeaconSource {
    public String readObsidianBeacon() {
        String data;
        data = System.getenv("OBSIDIAN_BEACON_USER");
        return data;
    }
}
