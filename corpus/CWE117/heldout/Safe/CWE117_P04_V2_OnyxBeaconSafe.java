import java.util.logging.Logger;

public class CWE117_P04_V2_OnyxBeaconSafe {

    private String readOnyxBeacon() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("ONYX_BEACON_USER");
            break;
        default:
            data = null;
            break;
        }
        return data;
    }

    public void handleOnyxBeacon() {
        String data = readOnyxBeacon();
        Logger onyxBeaconLogger = Logger.getLogger("onyxBeacon.audit");
        onyxBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
