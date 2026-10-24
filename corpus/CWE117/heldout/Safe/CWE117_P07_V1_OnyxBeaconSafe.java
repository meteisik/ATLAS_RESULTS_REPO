import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxBeaconSafe {

    public void handleOnyxBeacon() {
        String data;
        data = (new CWE117_P07_V1_OnyxBeaconSafeSource()).readOnyxBeacon();
        Logger onyxBeaconLogger = Logger.getLogger("onyxBeacon.audit");
        onyxBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_OnyxBeaconSafeSource {
    public String readOnyxBeacon() {
        String data;
        data = System.getenv("ONYX_BEACON_USER");
        return data;
    }
}
