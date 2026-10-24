import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianBeacon {

    public void handleObsidianBeacon() {
        String data;
        data = System.getenv("OBSIDIAN_BEACON_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianBeaconSink()).logObsidianBeacon(dataArray);
    }
}

class CWE117_P08_V1_ObsidianBeaconSink {
    public void logObsidianBeacon(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianBeaconLogger = Logger.getLogger("obsidianBeacon.audit");
        obsidianBeaconLogger.info("Login attempt for user " + data);
    }
}
