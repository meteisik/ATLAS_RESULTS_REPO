import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxBeacon {

    public void handleOnyxBeacon() {
        String data;
        data = (new CWE117_P07_V1_OnyxBeaconSource()).readOnyxBeacon();
        Logger onyxBeaconLogger = Logger.getLogger("onyxBeacon.audit");
        onyxBeaconLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_OnyxBeaconSource {
    public String readOnyxBeacon() {
        String data;
        data = System.getenv("ONYX_BEACON_USER");
        return data;
    }
}
