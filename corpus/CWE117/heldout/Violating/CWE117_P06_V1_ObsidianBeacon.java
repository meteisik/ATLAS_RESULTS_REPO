import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianBeacon {

    public void handleObsidianBeacon() {
        String data;
        data = System.getenv("OBSIDIAN_BEACON_USER");
        (new CWE117_P06_V1_ObsidianBeaconSink()).logObsidianBeacon(data);
    }
}

class CWE117_P06_V1_ObsidianBeaconSink {
    public void logObsidianBeacon(String data) {
        Logger obsidianBeaconLogger = Logger.getLogger("obsidianBeacon.audit");
        obsidianBeaconLogger.info("Login attempt for user " + data);
    }
}
